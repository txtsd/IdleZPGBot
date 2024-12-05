import asyncio
import base64
import ssl

import aiosqlite
import toml


class IdleZPGBot:
    """
    An IRCv3 bot that connects to an IRC server using SSL/TLS, authenticates using
    SASL PLAIN mechanism, awards experience points to users idling in the channel,
    and stores users' data in an SQLite database using aiosqlite.
    """

    def __init__(self, config):
        """
        Initialize the bot with the given configuration.

        Args:
            config (dict): Configuration dictionary loaded from a TOML file.
        """
        self.config = config
        self.reader = None
        self.writer = None
        self.channel = self.config['irc']['channel']
        self.users = set()  # Users currently in the channel
        self.xp_interval = 60  # Time interval in seconds to award XP
        self.xp_per_interval = 10  # XP awarded per interval
        self.xp_per_second = self.xp_per_interval / self.xp_interval  # XP awarded per second
        self.xp_task = None  # Background task for awarding XP
        self.db = None  # Database connection
        self.cumulative_xp = self.precompute_cumulative_xp(100)  # Precompute XP thresholds up to level 100
        self.nickname = self.config['irc']['nickname']  # Bot's own nickname

    async def connect(self):
        """
        Establish a secure connection to the IRC server and initiate SASL authentication.
        """
        # Extract IRC configuration parameters
        server = self.config['irc']['server']
        port = self.config['irc']['port']
        nickname = self.config['irc']['nickname']
        username = self.config['irc']['username']
        realname = self.config['irc']['realname']

        # Create a default SSL context for secure connection
        ssl_context = ssl.create_default_context()

        # Open a connection to the server with SSL
        self.reader, self.writer = await asyncio.open_connection(server, port, ssl=ssl_context)

        # Request SASL authentication capability
        self.send_raw('CAP REQ :sasl')

        # Send NICK and USER commands as per IRC protocol
        self.send_raw(f'NICK {nickname}')
        self.send_raw(f'USER {username} 0 * :{realname}')

    async def initialize_database(self):
        """
        Initialize the SQLite database and create the users table if it doesn't exist.
        """
        db_name = self.config['database']['path']
        self.db = await aiosqlite.connect(db_name)
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                nickname TEXT PRIMARY KEY,
                xp INTEGER NOT NULL DEFAULT 0,
                level INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Check if 'level' column exists; if not, add it
        async with self.db.execute('PRAGMA table_info(users)') as cursor:
            columns = await cursor.fetchall()
            column_names = [column[1] for column in columns]
            if 'level' not in column_names:
                await self.db.execute('ALTER TABLE users ADD COLUMN level INTEGER NOT NULL DEFAULT 0')
        await self.db.commit()

    async def process_messages(self):
        """
        Main loop to process incoming messages from the IRC server.

        Handles PING/PONG keep-alive messages, manages SASL authentication steps,
        joins the specified channel after successful login, and updates user lists.
        """
        # Extract required credentials from configuration
        nickname = self.config['irc']['nickname']
        password = self.config['irc']['nickserv_password']

        while True:
            try:
                # Read data from the server
                data = await self.reader.read(4096)
                if not data:
                    # No data indicates the server has closed the connection
                    break

                # Decode the received data to a string
                message = data.decode('utf-8', errors='ignore').strip()
                lines = message.split('\r\n')
                for line in lines:
                    if not line:
                        continue
                    print(f'{line}')

                    # Respond to server PING messages to keep the connection alive
                    if line.startswith('PING'):
                        self.send_raw(f'PONG {line[5:]}')

                    # Handle server acknowledgment of SASL capability
                    elif 'CAP * ACK :sasl' in line:
                        # Begin SASL authentication process
                        self.send_raw('AUTHENTICATE PLAIN')

                    # Server prompts for authentication credentials
                    elif 'AUTHENTICATE +' in line:
                        # Prepare credentials in the format: \0username\0password
                        credentials = f'\0{nickname}\0{password}'.encode('utf-8')
                        # Encode credentials in Base64 as required by SASL PLAIN mechanism
                        auth_message = base64.b64encode(credentials).decode('utf-8')
                        self.send_raw(f'AUTHENTICATE {auth_message}')

                    # SASL authentication was successful
                    elif '903' in line:
                        print('SASL authentication successful')
                        # End capability negotiation
                        self.send_raw('CAP END')

                    # SASL authentication failed
                    elif '904' in line or '905' in line:
                        print('SASL authentication failed')
                        return  # Exit the loop and disconnect

                    # Server has sent the Message of the Day (MOTD), indicating login is complete
                    elif '376' in line or '422' in line:
                        # Proceed to join the specified channel
                        await self.join_channel()

                    # Handle names reply to get the list of users upon joining the channel
                    elif '353' in line:
                        names = line.split(' :', 1)[1].split()
                        for user in names:
                            user = user.lstrip('@+%&~')
                            if user != nickname:
                                self.users.add(user)
                                await self.ensure_user_in_db(user)

                    # Handle JOIN messages
                    elif 'JOIN' in line:
                        prefix = line.split('!', 1)[0][1:]
                        if prefix != nickname:
                            self.users.add(prefix)
                            await self.ensure_user_in_db(prefix)
                            print(f'{prefix} joined the channel.')

                    # Handle PART messages
                    elif 'PART' in line:
                        prefix = line.split('!', 1)[0][1:]
                        self.users.discard(prefix)
                        print(f'{prefix} left the channel.')

                    # Handle QUIT messages
                    elif 'QUIT' in line:
                        prefix = line.split('!', 1)[0][1:]
                        self.users.discard(prefix)
                        print(f'{prefix} quit the server.')

                await self.writer.drain()

            except asyncio.CancelledError:
                # Handle task cancellation gracefully
                print('Task cancelled during message processing.')
                break

    async def ensure_user_in_db(self, nickname):
        """
        Ensure that a user's record exists in the database.

        Args:
            nickname (str): The nickname of the user.
        """
        if nickname == self.nickname:
            return  # Do not add the bot itself to the database

        async with self.db.execute('SELECT xp, level FROM users WHERE nickname = ?', (nickname,)) as cursor:
            row = await cursor.fetchone()
            if row is None:
                # User not in database, insert them at level 0
                await self.db.execute('INSERT INTO users (nickname, xp, level) VALUES (?, ?, ?)', (nickname, 0, 0))
                await self.db.commit()
                print(f'Added new user to database: {nickname}')

                # Send welcome message with time until next level
                time_remaining = self.time_until_next_level(0, 0)
                time_formatted = self.format_time(time_remaining)
                message = f'Welcome {nickname}! Time until next level: {time_formatted}'
                self.send_channel_message(message)

    def precompute_cumulative_xp(self, max_level):
        """
        Precompute cumulative XP required to reach each level up to max_level.

        Args:
            max_level (int): The maximum level to compute XP thresholds for.

        Returns:
            list: List of cumulative XP thresholds indexed by level.
        """
        cumulative_xp = [0] * (max_level + 2)  # Adjusted to start from level 0
        xp_per_second = self.xp_per_interval / self.xp_interval

        # Level 0 starts at XP 0
        cumulative_xp[0] = 0

        # Precompute XP for levels 1 to 60
        for level in range(1, 61):
            time_to_level = 600 * (1.16 ** (level - 1))  # Adjusted exponent
            xp_to_level = time_to_level * xp_per_second
            cumulative_xp[level] = cumulative_xp[level - 1] + xp_to_level

        # Precompute XP for levels above 60
        time_to_level_60 = 600 * (1.16**59)
        xp_to_level_60 = time_to_level_60 * xp_per_second
        for level in range(61, max_level + 1):
            time_to_level = time_to_level_60 + 86400 * (level - 60)
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
            return float('inf')  # No more levels defined
        xp_needed = self.cumulative_xp[next_level] - xp
        time_remaining = xp_needed / self.xp_per_second
        return time_remaining

    def format_time(self, seconds):
        """
        Format time in seconds into a human-readable string.

        Args:
            seconds (float): Time in seconds.

        Returns:
            str: Formatted time string.
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

    async def award_experience(self):
        """
        Background task to award experience points to users in the channel.
        """
        while True:
            await asyncio.sleep(self.xp_interval)
            if not self.users:
                continue  # No users to award XP to
            async with self.db.execute('BEGIN TRANSACTION;'):
                for user in self.users:
                    # Fetch current XP and level
                    async with self.db.execute('SELECT xp, level FROM users WHERE nickname = ?', (user,)) as cursor:
                        row = await cursor.fetchone()
                        if row:
                            current_xp, current_level = row
                            new_xp = current_xp + self.xp_per_interval
                            new_level = current_level
                            leveled_up = False

                            # Debug: Print current status
                            print(f'User: {user}, Current XP: {current_xp}, Current Level: {current_level}')

                            # Check for level-ups
                            while (
                                new_level + 1 < len(self.cumulative_xp) and new_xp >= self.cumulative_xp[new_level + 1]
                            ):
                                new_level += 1
                                leveled_up = True
                                print(f'{user} has leveled up to level {new_level}!')

                            # Update user's XP and level
                            await self.db.execute(
                                'UPDATE users SET xp = ?, level = ? WHERE nickname = ?', (new_xp, new_level, user)
                            )

                            if leveled_up:
                                # Announce level-up in the channel
                                time_remaining = self.time_until_next_level(new_level, new_xp)
                                time_formatted = self.format_time(time_remaining)
                                message = f'Congratulations {user} on reaching level {new_level}! Time until next level: {time_formatted}'
                                self.send_channel_message(message)
                    # No XP gain announcements needed
                await self.db.commit()
                # Debug: Indicate that XP has been awarded
                print(f'Awarded {self.xp_per_interval} XP to users.')

    async def join_channel(self):
        """
        Join the channel specified in the configuration.

        Should be called after successfully connecting and authenticating with the server.
        """
        await self.initialize_database()
        self.send_raw(f'JOIN {self.channel}')
        print(f'Joining channel: {self.channel}')
        # Start the background task for awarding experience
        self.xp_task = asyncio.create_task(self.award_experience())

    def send_raw(self, message):
        """
        Send a raw IRC message to the server.

        Args:
            message (str): The raw IRC message to send.
        """
        print(f'SENT: {message}')
        # Send the message followed by the IRC message terminator '\r\n'
        self.writer.write(f'{message}\r\n'.encode('utf-8'))

    def send_channel_message(self, message):
        """
        Send a message to the channel.

        Args:
            message (str): The message to send.
        """
        self.send_raw(f'PRIVMSG {self.channel} :{message}')

    async def disconnect(self):
        """
        Gracefully disconnect from the IRC server by sending the QUIT command.
        """
        # Get a custom quit message from the configuration, or use a default
        quit_message = self.config['irc'].get('quit_message', 'Goodbye!')
        try:
            # Send the QUIT command to the server
            self.send_raw(f'QUIT :{quit_message}')
            await self.writer.drain()
        except Exception as e:
            print(f'Error while sending QUIT: {e}')
        finally:
            if self.writer:
                print('Closing connection...')
                # Cancel the background XP task if it's running
                if self.xp_task:
                    self.xp_task.cancel()
                    try:
                        await self.xp_task
                    except asyncio.CancelledError:
                        pass
                # Close the writer stream to terminate the connection
                self.writer.close()
                await self.writer.wait_closed()
            if self.db:
                await self.db.close()
            print('Disconnected from the server.')


async def run():
    """
    Load the configuration and run the IRC bot.

    Handles exceptions and ensures the bot disconnects properly upon termination.
    """
    # Load configuration from 'config.toml' file
    config = toml.load('config.toml')

    # Instantiate the IRC bot with the loaded configuration
    bot = IdleZPGBot(config)

    try:
        # Connect to the server and process messages
        await bot.connect()
        await bot.process_messages()
    except KeyboardInterrupt:
        # Handle user interrupt (Ctrl+C)
        print('Keyboard interrupt received. Exiting...')
    except ssl.SSLError as e:
        # Handle SSL errors during connection
        print(f'SSL error: {e}')
    except Exception as e:
        # Handle any other unexpected exceptions
        print(f'Unexpected error: {e}')
    finally:
        # Ensure the bot disconnects cleanly
        await bot.disconnect()


def main():
    """
    Entry point for the program.

    Runs the asyncio event loop and handles keyboard interrupts.
    """
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print('Program terminated.')


if __name__ == '__main__':
    main()
