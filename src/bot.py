import asyncio
import base64
import random
import ssl
import time
from typing import Optional, Set

from aiosqlite import Connection
from argon2 import PasswordHasher

from logging_config import bot_logger, irc_logger, privmsg_logger
from utils import is_valid_name, strip_leading_the
from database import initialize_database


class IdleZPGBot:
    """
    An IRCv3 bot that connects to an IRC server using SSL/TLS, authenticates using the SASL PLAIN mechanism, awards
    experience points to users idling in the channel, and stores users' data in an SQLite database using aiosqlite.

    Features:
    - Secure connection to IRC servers using SSL/TLS.
    - SASL PLAIN authentication for secure login.
    - Periodic awarding of experience points (XP) to users idling in the channel.
    - Management of user data, including XP and levels, in an SQLite database.
    - Application of penalties for actions like talking, parting, quitting, and changing nicks.
    - User registration and unregistration for character management.
    """

    def __init__(self, config):
        """
        Initialize the bot with the given configuration.

        Args:
            config (dict): Configuration dictionary loaded from a TOML file.

        This method sets up the bot's configuration, initializes internal state,
        and precomputes XP thresholds for leveling up.
        """
        self.config = config

        # Stream reader for incoming data from the server.
        self.reader: Optional[asyncio.StreamReader] = None

        # Stream writer for sending data to the server.
        self.writer: Optional[asyncio.StreamWriter] = None

        # The IRC channel to join.
        self.channel = self.config['irc']['channel']

        # Set of users currently in the channel.
        self.users: Set[str] = set()

        # Time interval in seconds to award XP.
        self.xp_interval = self.config['game']['xp_interval']

        # XP awarded per interval.
        self.xp_per_interval = self.config['game']['xp_per_interval']

        # XP awarded per second.
        self.xp_per_second = self.xp_per_interval / self.xp_interval

        # Background task for awarding XP.
        self.xp_task: Optional[asyncio.Task] = None

        # Task for processing messages.
        self.message_task: Optional[asyncio.Task] = None

        # Database connection.
        self.db: Optional[Connection] = None

        # Maximum level for characters.
        self.max_level = self.config['game']['max_level']

        # Base time for level-up calculations.
        self.precompute_base_time = self.config['game']['precompute_base_time']

        # Exponent for level-up time scaling.
        self.precompute_exponent = self.config['game']['precompute_exponent']

        # Additional time per level after level 60.
        self.additional_time_per_level = self.config['game']['additional_time_per_level']

        # Precompute XP thresholds up to max_level.
        self.cumulative_xp = self.precompute_cumulative_xp(self.max_level)

        # Bot's own nickname.
        self.nickname = self.config['irc']['nickname']

        # Password hasher for secure password storage.
        self.ph = PasswordHasher()

        # Connection status flag.
        self.connected = False

        # Users to ignore for XP awards and penalties.
        self.ignored_users = self.config['irc'].get('ignored_users', [self.nickname, 'ChanServ'])

        # Flag to indicate shutdown.
        self.shutdown = False

        # Multiplier for penalty XP.
        self.penalty_multiplier = self.config['game'].get('penalty_multiplier', 1.0)

        # Define the item types
        self.item_types = [
            'ring',
            'amulet',
            'charm',
            'weapon',
            'helm',
            'armor',
            'set of gloves',
            'set of leggings',
            'shield',
            'set of boots',
        ]

    async def connect(self):
        """
        Establish a secure connection to the IRC server and initiate SASL authentication.

        This method sets up an SSL/TLS connection to the specified IRC server,
        requests SASL authentication capability, and sends the initial NICK and USER commands.
        """
        # Extract IRC configuration parameters.
        server = self.config['irc']['server']
        port = self.config['irc']['port']
        nickname = self.config['irc']['nickname']
        username = self.config['irc']['username']
        realname = self.config['irc']['realname']

        # Reset connection status.
        self.connected = False

        # Create a default SSL context for secure connection.
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        # Open a connection to the server with SSL.
        self.reader, self.writer = await asyncio.open_connection(server, port, ssl=ssl_context)

        # Request SASL authentication capability.
        self.send_raw('CAP REQ :sasl')

        # Send NICK and USER commands per IRC protocol.
        self.send_raw(f'NICK {nickname}')
        self.send_raw(f'USER {username} 0 * :{realname}')

        # Update connection status.
        self.connected = True

    async def process_messages(self):
        """
        Main loop to process incoming messages from the IRC server.

        This asynchronous method continuously reads messages from the IRC server,
        handles server commands, and responds appropriately.
        """
        # Extract required credentials and settings from configuration.
        nickname = self.config['irc']['nickname']
        password = self.config['irc']['nickserv_password']
        timeout = self.config['irc']['read_timeout']

        while not self.shutdown:
            try:
                if self.reader is None:
                    raise RuntimeError('Reader is not initialized')

                # Read data from the server with a timeout.
                data = await asyncio.wait_for(self.reader.read(4096), timeout=timeout)
                if not data:
                    # No data indicates the server has closed the connection.
                    raise ConnectionResetError('Connection lost')

                # Decode the received data to a string.
                message = data.decode('utf-8', errors='ignore').strip()
                lines = message.split('\r\n')
                for line in lines:
                    if not line:
                        continue
                    # Log received line.
                    irc_logger.debug(f'{line}')

                    # Handle the IRC line.
                    await self.handle_irc_line(line, nickname, password)

                if self.writer is None:
                    raise RuntimeError('Writer is not initialized')

                # Ensure all data is sent.
                await self.writer.drain()

            except asyncio.TimeoutError:
                bot_logger.error(f'Read timeout. No data received from server in {timeout} seconds.')
                raise ConnectionResetError('Connection lost due to timeout.')
            except KeyboardInterrupt as e:
                # Handle keyboard interrupt.
                bot_logger.warning('KeyboardInterrupt during message processing.')
                raise e
            except asyncio.CancelledError:
                bot_logger.warning('Task cancelled during message processing.')
                return
            except ssl.SSLError as e:
                # Handle SSL errors, such as receiving data after close_notify.
                bot_logger.error(f'SSL error in process_messages: {e}')
                # Exit the loop to allow for reconnect or clean shutdown.
                raise e
            except ConnectionResetError as e:
                # Connection was lost.
                bot_logger.error(f'ConnectionResetError: {e}')
                # Exit the loop to trigger reconnect.
                break
            except Exception as e:
                if self.shutdown:
                    bot_logger.error(f'Error in process_messages during shutdown: {e}')
                    return
                bot_logger.error(f'Error in process_messages: {e}')
                # Exit the loop to trigger reconnect.
                break

        bot_logger.info('Exiting process_messages loop.')

    async def handle_irc_line(self, line, nickname, password):
        """
        Handle a single line of IRC message.

        Args:
            line (str): The raw IRC message line.
            nickname (str): The bot's nickname.
            password (str): The bot's password for authentication.
        """
        # Respond to server PING messages to keep the connection alive.
        if line.startswith('PING'):
            self.send_raw(f'PONG {line[5:]}')
            return

        # Parse the IRC message line into prefix, command, and params.
        prefix, command, params = self.parse_irc_line(line)

        # Extract the sender's nick from the prefix.
        sender_nick = self.extract_nick_from_prefix(prefix)

        # Handle various IRC commands.
        if command == 'CAP' and 'ACK' in params:
            await self.handle_cap_ack(params)
        elif command == 'AUTHENTICATE' and params[0] == '+':
            await self.handle_authenticate(nickname, password)
        elif command == '903':
            await self.handle_auth_success()
        elif command == '904' or command == '905':
            await self.handle_auth_failure()
        elif command == '376' or command == '422':
            await self.handle_motd_complete()
        elif command == '353':
            await self.handle_names_reply(params)
        elif command == 'JOIN':
            await self.handle_join(sender_nick)
        elif command == 'PART':
            await self.handle_part(sender_nick)
        elif command == 'QUIT':
            await self.handle_quit(sender_nick)
        elif command == 'KICK':
            await self.handle_kick(params, sender_nick)
        elif command == 'NICK':
            await self.handle_nick_change(sender_nick, params)
        elif command == 'PRIVMSG':
            await self.handle_privmsg(sender_nick, params)
        elif command == 'NOTICE':
            await self.handle_notice(sender_nick, params)

    async def handle_cap_ack(self, params):
        """
        Handle CAP ACK command.

        Args:
            params (list): Parameters of the CAP command.
        """
        if 'sasl' in params:
            # Server acknowledges SASL capability, begin authentication.
            self.send_raw('AUTHENTICATE PLAIN')

    async def handle_authenticate(self, nickname, password):
        """
        Handle AUTHENTICATE command.

        Args:
            nickname (str): The bot's nickname.
            password (str): The bot's password for authentication.
        """
        # Prepare credentials in the format: \0username\0password.
        credentials = f'\0{nickname}\0{password}'.encode('utf-8')
        # Encode credentials in Base64 as required by SASL PLAIN mechanism.
        auth_message = base64.b64encode(credentials).decode('utf-8')
        self.send_raw(f'AUTHENTICATE {auth_message}')

    async def handle_auth_success(self):
        """
        Handle successful SASL authentication.
        """
        bot_logger.info('SASL authentication successful')
        # End capability negotiation.
        self.send_raw('CAP END')

    async def handle_auth_failure(self):
        """
        Handle failed SASL authentication.
        """
        bot_logger.error('SASL authentication failed')

    async def handle_motd_complete(self):
        """
        Handle completion of Message of the Day (MOTD).
        """
        # Proceed to join the specified channel.
        await self.join_channel()

    async def handle_names_reply(self, params):
        """
        Handle NAMES reply to get the list of users upon joining the channel.

        Args:
            params (list): Parameters of the NAMES command.
        """
        names = params[-1].split()
        # Clear existing users before updating.
        self.users.clear()
        for user in names:
            # Remove any user modes or prefixes.
            user = user.lstrip('@+%&~')
            if user not in self.ignored_users:
                self.users.add(user)
                bot_logger.debug(f'User in channel: {user}')

    async def handle_join(self, sender_nick):
        """
        Handle JOIN messages (when a user joins the channel).

        Args:
            sender_nick (str): Nickname of the user who joined.
        """
        if sender_nick not in self.ignored_users:
            self.users.add(sender_nick)
            bot_logger.info(f'{sender_nick} joined the channel.')

    async def handle_part(self, sender_nick):
        """
        Handle PART messages (when a user leaves the channel).

        Args:
            sender_nick (str): Nickname of the user who left.
        """
        self.users.discard(sender_nick)
        bot_logger.info(f'{sender_nick} left the channel.')
        if sender_nick not in self.ignored_users:
            await self.apply_penalty(sender_nick, reason='PART')

    async def handle_quit(self, sender_nick):
        """
        Handle QUIT messages (when a user disconnects from the server).

        Args:
            sender_nick (str): Nickname of the user who quit.
        """
        self.users.discard(sender_nick)
        bot_logger.info(f'{sender_nick} quit the server.')
        if sender_nick not in self.ignored_users:
            await self.apply_penalty(sender_nick, reason='QUIT')

    async def handle_kick(self, params, sender_nick):
        """
        Handle KICK command.

        Args:
            params (list): Parameters of the KICK command.
            sender_nick (str): Nickname of the user who issued the KICK.
        """
        channel = params[0]
        kicked_user = params[1]
        comment = params[2] if len(params) > 2 else ''
        if channel == self.channel:
            # User has been kicked from the channel.
            self.users.discard(kicked_user)
            bot_logger.info(f'{kicked_user} was kicked from {channel} by {sender_nick}. Reason: {comment}')
            if kicked_user not in self.ignored_users:
                await self.apply_penalty(kicked_user, reason='KICK')

    async def handle_nick_change(self, sender_nick, params):
        """
        Handle NICK messages (when a user changes their nickname).

        Args:
            sender_nick (str): Nickname of the user who changed their nick.
            params (list): Parameters of the NICK command.
        """
        new_nick = params[0]
        if sender_nick in self.users:
            self.users.discard(sender_nick)
            self.users.add(new_nick)
            bot_logger.info(f'{sender_nick} changed nick to {new_nick}')
            if sender_nick not in self.ignored_users:
                await self.apply_penalty(sender_nick, reason='NICK')
        if sender_nick == self.nickname:
            # Update bot's own nickname if it changed.
            self.nickname = new_nick

    async def handle_privmsg(self, sender_nick, params):
        """
        Handle PRIVMSG (private messages or channel messages).

        Args:
            sender_nick (str): Nickname of the sender.
            params (list): Parameters of the PRIVMSG command.
        """
        target = params[0]
        message_text = params[1] if len(params) > 1 else ''
        if target == self.nickname:
            # Private message to the bot.
            await self.handle_private_message(sender_nick, message_text)
        elif target == self.channel:
            # Message in the channel.
            privmsg_logger.info(f'{sender_nick} in channel: {message_text}')
            # Apply penalty for talking in the channel.
            if sender_nick not in self.ignored_users:
                message_length = len(message_text)
                await self.apply_penalty(sender_nick, reason='PRIVMSG', extra_info={'message_length': message_length})

    async def handle_notice(self, sender_nick, params):
        """
        Handle NOTICE messages.

        Args:
            sender_nick (str): Nickname of the sender.
            params (list): Parameters of the NOTICE command.
        """
        target = params[0]
        message_text = params[1] if len(params) > 1 else ''
        if target == self.channel:
            # A NOTICE message to the channel.
            privmsg_logger.info(f'{sender_nick} sent NOTICE to channel: {message_text}')
            # Apply penalty for sending NOTICE to the channel.
            if sender_nick not in self.ignored_users:
                message_length = len(message_text)
                await self.apply_penalty(sender_nick, reason='NOTICE', extra_info={'message_length': message_length})

    async def handle_private_message(self, sender_nick, message_text):
        """
        Handle private messages sent to the bot.

        Args:
            sender_nick (str): Nickname of the sender.
            message_text (str): The message content.

        This method processes private messages sent to the bot.
        It checks for registration or unregistration commands and handles them accordingly.
        """
        # Check if the message is a registration command.
        if message_text.strip().startswith('register'):
            args = message_text[len('register') :].strip()
            await self.handle_register_command(sender_nick, args)
        elif message_text.strip() == 'unregister':
            # Handle unregistration command.
            await self.handle_unregister_command(sender_nick)
        elif message_text.strip() == 'help':
            # Handle help command.
            await self.handle_help_command(sender_nick)
        elif message_text.strip() == 'info':
            # Handle info command.
            await self.handle_info_command(sender_nick)
        else:
            # Optionally, handle other private messages or send a help message.
            await self.handle_help_command(sender_nick)

    async def handle_register_command(self, sender_nick, args):
        """
        Handle the 'register' command sent by a user.

        Args:
            sender_nick (str): Nickname of the sender.
            args (str): Arguments passed with the register command.

        This method allows a user to register a new character with the bot.
        It validates the input, hashes the password, checks for existing characters, and adds the character to the database.
        """
        registration_help_message = (
            'To register, use: register <character_name> <class_name> <password>\n'
            'Example: register Ragnarr_loðbrók Legendary Viking password123!@#'
        )

        try:
            if self.db is None:
                raise RuntimeError('Database connection is not initialized')

            # Check if the user has already registered.
            async with self.db.execute(
                'SELECT character_name FROM characters WHERE owner_nick = ?', (sender_nick,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    raise ValueError('You have already registered a character.')

            if not args:
                raise ValueError(registration_help_message)

            # Split the arguments into parts.
            parts = args.split()
            if len(parts) < 3:
                raise ValueError(registration_help_message)

            character_name = parts[0]
            class_name = ' '.join(parts[1:-1])
            password = parts[-1]

            # Strip leading 'the' from class name.
            class_name = strip_leading_the(class_name)

            # Validate character_name and class_name (<=16 characters).
            is_valid, error_message = is_valid_name(character_name)
            if not is_valid:
                raise ValueError(f'Invalid character name: {error_message}')
            is_valid, error_message = is_valid_name(class_name, allow_spaces=True)
            if not is_valid:
                raise ValueError(f'Invalid class name: {error_message}')

            # Hash the password using Argon2.
            password_hash = self.ph.hash(password)

            # Check if the character name is already taken.
            async with self.db.execute(
                'SELECT character_name FROM characters WHERE character_name = ?', (character_name,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    raise ValueError(f'Character name {character_name} is already taken.')

            # Insert the new character into the database.
            await self.db.execute(
                'INSERT INTO characters (character_name, class_name, password_hash, owner_nick, xp, level) VALUES (?, ?, ?, ?, ?, ?)',
                (character_name, class_name, password_hash, sender_nick, 0, 0),
            )
            await self.db.commit()

            # Send success message to the user.
            success_message = (
                f'Registration successful! Your character {character_name}, the {class_name}, has been created.\n'
                'The purpose of the game is to idle in the channel and level up your character. '
                'Talking, parting, quitting, and changing nicks have penalties.'
            )
            self.send_notice(sender_nick, success_message)

            # Calculate time until next level.
            time_remaining = self.time_until_next_level(0, 0)
            time_formatted = self.format_time(time_remaining)

            # Announce in the channel.
            channel_message = f"Welcome {sender_nick}'s new player: {character_name}, the {class_name}! Time until next level: {time_formatted}"
            self.send_channel_message(channel_message)

            bot_logger.info(f'User {sender_nick} registered character {character_name}, the {class_name}')
        except ValueError as e:
            # Send error message to the user.
            error_message = str(e)
            self.send_notice(sender_nick, error_message)
            bot_logger.error(f'Registration failed for user {sender_nick}: {str(e)}')

    async def handle_unregister_command(self, sender_nick):
        """
        Handle the 'unregister' command sent by a user.

        Args:
            sender_nick (str): Nickname of the sender.

        This method allows a user to unregister their character from the bot.
        It removes the character associated with the user's nickname from the database.
        """
        if self.db is None:
            raise RuntimeError('Database connection is not initialized')

        try:
            # Check if the user has registered.
            async with self.db.execute(
                'SELECT character_name FROM characters WHERE owner_nick = ?', (sender_nick,)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    raise ValueError('You have not registered a character.')

            character_name = row[0]

            # Delete the character from the database.
            await self.db.execute('DELETE FROM characters WHERE owner_nick = ?', (sender_nick,))
            await self.db.commit()

            # Send success message to the user.
            success_message = f'Your character {character_name} has been unregistered.'
            self.send_notice(sender_nick, success_message)

            # Announce in the channel.
            channel_message = f'{sender_nick} has unregistered their character {character_name}.'
            self.send_channel_message(channel_message)

            bot_logger.info(f'User {sender_nick} unregistered character {character_name}')
        except ValueError as e:
            # Send error message to the user.
            error_message = str(e)
            self.send_notice(sender_nick, error_message)
            bot_logger.error(f'Unregister failed for user {sender_nick}: {str(e)}')

    async def handle_help_command(self, sender_nick):
        """
        Handle the 'help' command sent by a user.

        Args:
            sender_nick (str): Nickname of the sender.

        This method sends a list of available commands to the user.
        """
        help_message = (
            'Available commands:\n'
            'register <character_name> <class_name> <password> - Register a new character.\n'
            'unregister - Unregister your character.\n'
            'help - Show this help message.'
        )
        self.send_notice(sender_nick, help_message)

    async def handle_info_command(self, sender_nick):
        """
        Handle the 'info' command sent by a user.

        Args:
            sender_nick (str): Nickname of the sender.

        This method sends information about the bot and lists online operators.
        """
        bot_info = (
            'IdleZPGBot\n'
            'Version: 0.0.3\n'
            'Source: https://github.com/txtsd/IdleZPGBot\n'
            'Admins online: '
        )
        # List online operators excluding ignored users
        operators_online = [user for user in self.users if user in self.config['irc'].get('operators', []) and user not in self.ignored_users]
        operators_list = ', '.join(operators_online) if operators_online else 'None'
        info_message = f"{bot_info}{operators_list}"
        self.send_notice(sender_nick, info_message)

    async def apply_penalty(self, nick, reason='', extra_info=None):
        """
        Apply penalty to the character associated with the given nick.

        Args:
            nick (str): Nickname of the user.
            reason (str): Reason for the penalty (e.g., 'PRIVMSG', 'PART', 'QUIT', 'NICK', 'KICK', 'NOTICE').
            extra_info (dict): Additional information needed for calculating penalty (e.g., message_length).

        This method deducts XP from the character associated with the given
        nickname and handles level-down if necessary. It also announces
        penalties and level changes in the channel, and informs the user
        about the time until their next level.
        """
        if extra_info is None:
            extra_info = {}

        if self.db is None:
            raise RuntimeError('Database connection is not initialized')

        # Fetch the character associated with the nick.
        async with self.db.execute(
            'SELECT character_name, class_name, xp, level FROM characters WHERE owner_nick = ?', (nick,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                character_name, class_name, current_xp, current_level = row

                # Calculate penalty_xp based on reason and current_level
                reason_upper = reason.upper()
                if reason_upper == 'NICK':
                    penalty_xp = 30 * (1.14**current_level)
                elif reason_upper == 'PART':
                    penalty_xp = 200 * (1.14**current_level)
                elif reason_upper == 'QUIT':
                    penalty_xp = 20 * (1.14**current_level)
                elif reason_upper == 'KICK':
                    penalty_xp = 250 * (1.14**current_level)
                elif reason_upper == 'PRIVMSG':
                    message_length = extra_info.get('message_length', 0)
                    penalty_xp = message_length * (1.14**current_level)
                elif reason_upper == 'NOTICE':
                    message_length = extra_info.get('message_length', 0)
                    penalty_xp = message_length * (1.14**current_level)
                else:
                    # Default penalty
                    penalty_xp = self.xp_per_interval * self.penalty_multiplier

                new_xp = max(current_xp - penalty_xp, 0)
                new_level = current_level
                leveled_down = False

                # Check for level-downs.
                while new_level > 0 and new_xp < self.cumulative_xp[new_level]:
                    new_level -= 1
                    leveled_down = True
                    bot_logger.info(f'{character_name} has leveled down to level {new_level}!')

                # Update character's XP and level.
                await self.db.execute(
                    'UPDATE characters SET xp = ?, level = ? WHERE character_name = ?',
                    (new_xp, new_level, character_name),
                )
                await self.db.commit()

                # Calculate time until next level
                time_remaining = self.time_until_next_level(new_level, new_xp)
                time_formatted = self.format_time(time_remaining)

                # Prepare the time until next level message
                time_message = f'Time until next level: {time_formatted}'

                if leveled_down:
                    # Announce level-down in the channel.
                    level_down_message = (
                        f"{nick}'s character {character_name} has dropped to level {new_level}. {time_message}"
                    )
                    self.send_channel_message(level_down_message)

                # Map reason to 'reasoning' form for the message.
                reason_ing_map = {
                    'PART': 'parting',
                    'QUIT': 'quitting',
                    'PRIVMSG': 'talking',
                    'NOTICE': 'talking',
                    'NICK': 'changing nick',
                    'KICK': 'being kicked',
                }
                reason_text = reason_ing_map.get(reason_upper, reason.lower() + 'ing')

                # Send the public penalty message.
                public_message = f"{nick}'s character {character_name}, the {class_name}, has been penalized for {reason_text}. {time_message}"
                self.send_channel_message(public_message)

                # Notify the user about the penalty.
                penalty_message = f'Your character {character_name}, the {class_name}, has been penalized for {reason_text}. {time_message}'
                self.send_notice(nick, penalty_message)

    @staticmethod
    def parse_irc_line(line):
        """
        Parse a single line of IRC message.

        Args:
            line (str): The raw line.

        Returns:
            tuple: (prefix, command, params)
                - prefix (str): The prefix of the message (sender information).
                - command (str): The IRC command or numeric response code.
                - params (list): Parameters or arguments of the command.
        """
        prefix = ''
        trailing = []
        if line.startswith(':'):
            prefix, line = line[1:].split(' ', 1)
        if ' :' in line:
            line, trailing = line.split(' :', 1)
            args = line.strip().split()
            args.append(trailing)
        else:
            args = line.strip().split()
        if not args:
            command = ''
        else:
            command = args.pop(0)
        return prefix, command, args

    @staticmethod
    def extract_nick_from_prefix(prefix):
        """
        Extract the nickname from the prefix.

        Args:
            prefix (str): The prefix string.

        Returns:
            str: Nickname extracted from the prefix.
        """
        if '!' in prefix:
            nick = prefix.split('!', 1)[0]
        else:
            nick = prefix
        return nick

    def precompute_cumulative_xp(self, max_level):
        """
        Precompute cumulative XP required to reach each level up to max_level.

        Args:
            max_level (int): The maximum level to compute XP thresholds for.

        Returns:
            list: List of cumulative XP thresholds indexed by level.
        """
        # Adjusted to start from level 0.
        cumulative_xp = [0] * (max_level + 2)
        xp_per_second = self.xp_per_second

        # Level 0 starts at XP 0.
        cumulative_xp[0] = 0

        base_time = self.precompute_base_time
        exponent = self.precompute_exponent
        additional_time_per_level = self.additional_time_per_level

        # Precompute XP for levels 1 to 60.
        for level in range(1, 61):
            # Adjusted exponent for level-up time scaling.
            time_to_level = base_time * (exponent ** (level - 1))
            xp_to_level = time_to_level * xp_per_second
            cumulative_xp[level] = cumulative_xp[level - 1] + xp_to_level

        # Precompute XP for levels above 60.
        time_to_level_60 = base_time * (exponent**59)
        for level in range(61, max_level + 1):
            time_to_level = time_to_level_60 + additional_time_per_level * (level - 60)
            xp_to_level = time_to_level * xp_per_second
            cumulative_xp[level] = cumulative_xp[level - 1] + xp_to_level

        return cumulative_xp

    def time_until_next_level(self, level, xp):
        """
        Calculate the time remaining until the next level for a user.

        Args:
            level (int): The user's current level.
            xp (float): The user's current XP.

        Returns:
            float: Time in seconds until the next level.
        """
        next_level = level + 1
        if next_level >= len(self.cumulative_xp):
            # No more levels defined.
            return float('inf')
        xp_needed = self.cumulative_xp[next_level] - xp
        time_remaining = xp_needed / self.xp_per_second
        return time_remaining

    def format_time(self, seconds):
        """
        Format time in seconds into a human-readable string.

        Args:
            seconds (float): Time in seconds.

        Returns:
            str: Formatted time string in the format "Xd Xh Xm Xs".
        """
        seconds = int(seconds)
        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)
        parts = []
        if days > 0:
            parts.append(f'{days}d')
        if hours > 0 or days > 0:
            parts.append(f'{hours}h')
        if minutes > 0 or hours > 0 or days > 0:
            parts.append(f'{minutes}m')
        parts.append(f'{seconds}s')
        return ' '.join(parts)

    async def refresh_user_list(self):
        """
        Request an updated list of users in the channel.

        This method sends a NAMES command to the server to refresh the list
        of users in the channel.
        """
        self.send_raw(f'NAMES {self.channel}')

    async def award_experience(self):
        """
        Background task to award experience points to users in the channel.

        This method periodically awards XP to all users currently in the channel,
        checks for level-ups, and announces them in the channel.
        """
        # Refresh user list every X seconds.
        refresh_interval = self.config['game']['refresh_interval']
        last_refresh = time.monotonic()
        while self.connected:
            try:
                # Sleep for the XP awarding interval.
                await asyncio.sleep(self.xp_interval)
                if not self.connected:
                    bot_logger.info('Bot is disconnected. Stopping XP awards.')
                    break
                # No users to award XP to.
                if not self.users:
                    continue

                # Refresh user list periodically.
                current_time = time.monotonic()
                if current_time - last_refresh >= refresh_interval:
                    await self.refresh_user_list()
                    last_refresh = current_time

                if self.db is None:
                    raise RuntimeError('Database connection is not initialized')

                # Begin a transaction for XP updates.
                async with self.db.execute('BEGIN TRANSACTION;'):
                    for user in self.users:
                        # Fetch character associated with the user.
                        async with self.db.execute(
                            'SELECT character_name, class_name, xp, level FROM characters WHERE owner_nick = ?',
                            (user,),
                        ) as cursor:
                            row = await cursor.fetchone()
                            if row:
                                character_name, class_name, current_xp, current_level = row
                                new_xp = current_xp + self.xp_per_interval
                                new_level = current_level
                                leveled_up = False

                                # Log current status.
                                bot_logger.debug(
                                    f'User: {user}, Character: {character_name}, Class: {class_name}, Current XP: {current_xp}, Current Level: {current_level}'
                                )

                                # Check for level-ups.
                                while (
                                    new_level + 1 < len(self.cumulative_xp)
                                    and new_xp >= self.cumulative_xp[new_level + 1]
                                ):
                                    new_level += 1
                                    leveled_up = True
                                    bot_logger.info(f"{user}'s {character_name} has leveled up to level {new_level}!")

                                # Update character's XP and level.
                                await self.db.execute(
                                    'UPDATE characters SET xp = ?, level = ? WHERE character_name = ?',
                                    (new_xp, new_level, character_name),
                                )

                                if leveled_up:
                                    # Announce level-up in the channel.
                                    time_remaining = self.time_until_next_level(new_level, new_xp)
                                    time_formatted = self.format_time(time_remaining)
                                    # Updated message to include the class name.
                                    message = f"{user}'s character {character_name}, the {class_name}, has attained level {new_level}! Time until next level: {time_formatted}"
                                    self.send_channel_message(message)
                                    # Handle item finding
                                    await self.find_item(character_name, new_level, user)

                    # Commit the transaction.
                    await self.db.commit()
                    # Debug: Indicate that XP has been awarded.
                    bot_logger.info(f'Awarded {self.xp_per_interval} XP to characters.')
            except asyncio.CancelledError:
                bot_logger.warning('XP awarding task cancelled.')
                break
            except Exception as e:
                bot_logger.error(f'Error in award_experience: {e}')
                break

    async def find_item(self, character_name, new_level, user):
        """
        Handle item finding when a character levels up.

        Args:
            character_name (str): The character's name.
            new_level (int): The new level of the character.
            user (str): The user's nickname.

        This method calculates the probabilities of finding items of different levels,
        picks an item level and type based on these probabilities, and updates the character's
        items in the database accordingly.
        """
        max_item_level = int(new_level * 1.5)
        levels = []
        cumulative_weights = []
        total_weight = 0.0
        for level in range(1, max_item_level + 1):
            weight = 1 / (1.4**level)
            total_weight += weight
            levels.append(level)
            cumulative_weights.append(total_weight)

        # Generate a random number between 0 and total_weight
        rand = random.uniform(0, total_weight)

        # Find the item level based on random number
        for i, cumulative_weight in enumerate(cumulative_weights):
            if rand <= cumulative_weight:
                item_level = levels[i]
                break
        else:
            # In case of rounding errors
            item_level = levels[-1]

        # Randomly pick an item type
        item_type = random.choice(self.item_types)

        # Check if character has an item of this type
        if self.db is None:
            raise RuntimeError('Database connection is not initialized')

        # Check the highest level at which an item was awarded
        async with self.db.execute(
            'SELECT highest_item_level_awarded FROM characters WHERE character_name = ?', (character_name,)
        ) as cursor:
            row = await cursor.fetchone()
            if row and new_level <= row[0]:
                # Character has already been awarded an item at this level or higher
                message = f"{user}'s character {character_name} did not find a new item because they have already been awarded an item at level {row[0]} or higher."
                self.send_channel_message(message)
                return

        # Proceed to check if character has an item of this type
        async with self.db.execute(
            'SELECT item_level FROM items WHERE character_name = ? AND item_type = ?', (character_name, item_type)
        ) as cursor:
            row = await cursor.fetchone()

        if row:
            # Character already has an item of this type
            current_item_level = row[0]
            if item_level > current_item_level:
                # Replace the item in the database
                await self.db.execute(
                    'UPDATE items SET item_level = ? WHERE character_name = ? AND item_type = ?',
                    (item_level, character_name, item_type),
                )
                await self.db.commit()
                # Announce the item upgrade
                message = f"{user}'s character {character_name} found a level {item_level} {item_type} and replaced their old level {current_item_level} {item_type}!"
                self.send_channel_message(message)
            else:
                # Found an item, but it's not better than current one
                message = f"{user}'s character {character_name} found a level {item_level} {item_type}, but their current {item_type} is better."
                self.send_channel_message(message)
        else:
            # Character does not have an item of this type yet
            await self.db.execute(
                'INSERT INTO items (character_name, item_type, item_level) VALUES (?, ?, ?)',
                (character_name, item_type, item_level),
            )
            await self.db.commit()
            # Announce the new item
            message = f"{user}'s character {character_name} found a level {item_level} {item_type}!"
            self.send_channel_message(message)

        # Update the highest level at which an item was awarded
        await self.db.execute(
            'UPDATE characters SET highest_item_level_awarded = ? WHERE character_name = ?',
            (new_level, character_name),
        )
        await self.db.commit()

    async def join_channel(self):
        """
        Join the channel specified in the configuration.

        Should be called after successfully connecting and authenticating with the server.
        This method initializes the database and starts the background XP awarding task.
        """
        # Initialize the database.
        await initialize_database(self)
        # Send JOIN command to the server.
        self.send_raw(f'JOIN {self.channel}')
        bot_logger.info(f'Joining channel: {self.channel}')
        # Start the background task for awarding experience.
        self.xp_task = asyncio.create_task(self.award_experience())

    def send_raw(self, message):
        """
        Send a raw IRC message to the server.

        Args:
            message (str): The raw IRC message to send.
        """
        bot_logger.info(f'SENT: {message}')
        if self.writer is None:
            raise RuntimeError('Writer is not initialized')
        # Send the message followed by the IRC message terminator '\r\n'.
        self.writer.write(f'{message}\r\n'.encode('utf-8'))

    def send_channel_message(self, message):
        """
        Send a message to the channel.

        Args:
            message (str): The message to send.
        """
        self.send_raw(f'PRIVMSG {self.channel} :{message}')
        privmsg_logger.info(f'{self.nickname} in {self.channel}: {message}')

    def send_notice(self, target_nick, message):
        """
        Send a private message to a user.

        Args:
            target_nick (str): The nickname of the user.
            message (str): The message to send.
        """
        for line in message.split('\n'):
            self.send_raw(f'NOTICE {target_nick} :{line}')

    async def disconnect(self):
        """
        Gracefully disconnect from the IRC server by sending the QUIT command.

        This method ensures that all tasks are cancelled, the connection is closed,
        and the database is properly closed.
        """
        # Indicate that the bot is shutting down.
        self.shutdown = True
        # Get a custom quit message from the configuration, or use a default.
        quit_message = self.config['irc'].get('quit_message', 'Goodbye!')
        try:
            # Send the QUIT command to the server.
            self.send_raw(f'QUIT :{quit_message}')
            if self.writer is None:
                raise RuntimeError('Writer is not initialized')
            await self.writer.drain()
        except Exception as e:
            bot_logger.error(f'Error while sending QUIT: {e}')
        finally:
            # Cancel message processing task if it's running.
            if self.message_task is not None and not self.message_task.done():
                bot_logger.info('Cancelling message processing task...')
                self.message_task.cancel()
                try:
                    await self.message_task
                except asyncio.CancelledError:
                    pass
            if self.writer:
                bot_logger.info('Closing connection...')
                # Cancel the background XP task if it's running.
                if self.xp_task and not self.xp_task.done():
                    bot_logger.info('Cancelling XP awarding task...')
                    self.xp_task.cancel()
                    try:
                        await self.xp_task
                    except asyncio.CancelledError:
                        pass
                # Update connection status.
                self.connected = False
                # Clear the set of users.
                self.users.clear()
                # Close the writer stream to terminate the connection.
                # Wrap wait_closed() in a try-except to handle potential timeouts
                self.writer.close()
                try:
                    await self.writer.wait_closed()
                except TimeoutError as e:
                    bot_logger.error(f'TimeoutError during SSL shutdown: {e}')
                except Exception as e:
                    bot_logger.error(f'Error while waiting for writer to close: {e}', exc_info=True)
            if self.db:
                # Close the database connection.
                await self.db.close()
            bot_logger.info('Disconnected from the server.')
