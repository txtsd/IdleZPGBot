import asyncio
import base64
import ssl
from typing import Optional, Set

import aiosqlite
import toml
from aiosqlite import Connection
from argon2 import PasswordHasher


class IdleZPGBot:
  """
  An IRCv3 bot that connects to an IRC server using SSL/TLS, authenticates using
  SASL PLAIN mechanism, awards experience points to users idling in the channel,
  and stores users' data in an SQLite database using aiosqlite.

  Users must register a character with the bot to participate.
  """

  def __init__(self, config):
    """
    Initialize the bot with the given configuration.

    Args:
        config (dict): Configuration dictionary loaded from a TOML file.
    """
    self.config = config
    self.reader: Optional[asyncio.StreamReader] = None
    self.writer: Optional[asyncio.StreamWriter] = None
    self.channel = self.config['irc']['channel']
    self.users: Set[str] = set()  # Users currently in the channel
    self.xp_interval = 60  # Time interval in seconds to award XP
    self.xp_per_interval = 10  # XP awarded per interval
    self.xp_per_second = self.xp_per_interval / self.xp_interval  # XP awarded per second
    self.xp_task: Optional[asyncio.Task] = None  # Background task for awarding XP
    self.db: Optional[Connection] = None  # Database connection
    self.cumulative_xp = self.precompute_cumulative_xp(100)  # Precompute XP thresholds up to level 100
    self.nickname = self.config['irc']['nickname']  # Bot's own nickname
    self.ph = PasswordHasher()

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
    Initialize the SQLite database and create the characters table if it doesn't exist.
    """
    db_name = self.config['database']['path']
    self.db = await aiosqlite.connect(db_name)
    await self.db.execute("""
      CREATE TABLE IF NOT EXISTS characters (
          character_name TEXT PRIMARY KEY,
          class_name TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          owner_nick TEXT NOT NULL,
          xp INTEGER NOT NULL DEFAULT 0,
          level INTEGER NOT NULL DEFAULT 0
      )
    """)
    await self.db.commit()

  async def process_messages(self):
    """
    Main loop to process incoming messages from the IRC server.

    Handles PING/PONG keep-alive messages, manages SASL authentication steps,
    joins the specified channel after successful login, and updates user lists.

    Also handles registration commands and applies penalties.
    """
    # Extract required credentials from configuration
    nickname = self.config['irc']['nickname']
    password = self.config['irc']['nickserv_password']

    while True:
      try:
        if self.reader is None:
          raise RuntimeError('Reader is not initialized')

        # Read data from the server
        data = await self.reader.read(4096)
        if not data:
          # No data indicates the server has closed the connection
          raise ConnectionResetError('Connection lost')

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
            continue

          prefix, command, params = self.parse_irc_line(line)
          sender_nick = self.extract_nick_from_prefix(prefix)

          # Handle server acknowledgment of SASL capability
          if command == 'CAP' and 'ACK' in params:
            if 'sasl' in params:
              # Begin SASL authentication process
              self.send_raw('AUTHENTICATE PLAIN')

          # Server prompts for authentication credentials
          elif command == 'AUTHENTICATE' and params[0] == '+':
            # Prepare credentials in the format: \0username\0password
            credentials = f'\0{nickname}\0{password}'.encode('utf-8')
            # Encode credentials in Base64 as required by SASL PLAIN mechanism
            auth_message = base64.b64encode(credentials).decode('utf-8')
            self.send_raw(f'AUTHENTICATE {auth_message}')

          # SASL authentication was successful
          elif command == '903':
            print('SASL authentication successful')
            # End capability negotiation
            self.send_raw('CAP END')

          # SASL authentication failed
          elif command == '904' or command == '905':
            print('SASL authentication failed')
            return  # Exit the loop and disconnect

          # Server has sent the Message of the Day (MOTD), indicating login is complete
          elif command == '376' or command == '422':
            # Proceed to join the specified channel
            await self.join_channel()

          # Handle names reply to get the list of users upon joining the channel
          elif command == '353':
            names = params[-1].split()
            for user in names:
              user = user.lstrip('@+%&~')
              if user != nickname:
                self.users.add(user)
                print(f'User in channel: {user}')

          # Handle JOIN messages
          elif command == 'JOIN':
            if sender_nick != nickname:
              self.users.add(sender_nick)
              print(f'{sender_nick} joined the channel.')

          # Handle PART messages
          elif command == 'PART':
            self.users.discard(sender_nick)
            print(f'{sender_nick} left the channel.')
            await self.apply_penalty(sender_nick, reason='PART')

          # Handle QUIT messages
          elif command == 'QUIT':
            self.users.discard(sender_nick)
            print(f'{sender_nick} quit the server.')
            await self.apply_penalty(sender_nick, reason='QUIT')

          # Handle NICK changes
          elif command == 'NICK':
            new_nick = params[0]
            if sender_nick in self.users:
              self.users.discard(sender_nick)
              self.users.add(new_nick)
              print(f'{sender_nick} changed nick to {new_nick}')
              await self.apply_penalty(sender_nick, reason='NICK')
            if sender_nick == nickname:
              self.nickname = new_nick

          # Handle PRIVMSG
          elif command == 'PRIVMSG':
            target = params[0]
            message_text = params[1] if len(params) > 1 else ''
            if target == self.nickname:
              # Private message to the bot
              await self.handle_private_message(sender_nick, message_text)
            elif target == self.channel:
              # Message in the channel
              print(f'{sender_nick} in channel: {message_text}')
              # Apply penalty for talking in the channel
              await self.apply_penalty(sender_nick, reason='TALK')

        if self.writer is None:
          raise RuntimeError('Writer is not initialized')

        await self.writer.drain()

      except asyncio.CancelledError:
        # Handle task cancellation gracefully
        print('Task cancelled during message processing.')
        break
      except ConnectionResetError as e:
        # Connection was lost
        print(f'ConnectionResetError: {e}')
        raise e
      except Exception as e:
        print(f'Error in process_messages: {e}')
        raise e

  async def handle_private_message(self, sender_nick, message_text):
    """
    Handle private messages sent to the bot.

    Args:
        sender_nick (str): Nickname of the sender.
        message_text (str): The message content.
    """
    # Check if the message is a registration command
    if message_text.strip().startswith('register'):
      args = message_text[len('register') :].strip()
      await self.handle_register_command(sender_nick, args)
    elif message_text.strip() == 'unregister':
      await self.handle_unregister_command(sender_nick)

  async def handle_register_command(self, sender_nick, args):
    """
    Handle the 'register' command sent by a user.

    Args:
        sender_nick (str): Nickname of the sender.
        args (str): Arguments passed with the register command.
    """
    registration_help_message = (
      'To register, use: register <character_name> <class_name> <password>\n'
      'Example: register Ragnarr_loðbrók Legendary Viking password123!@#'
    )

    try:
      if self.db is None:
        raise RuntimeError('Database connection is not initialized')

      # Check if the user has already registered
      async with self.db.execute(
        'SELECT character_name FROM characters WHERE owner_nick = ?', (sender_nick,)
      ) as cursor:
        row = await cursor.fetchone()
        if row:
          raise ValueError('You have already registered a character.')

      if not args:
        raise ValueError(registration_help_message)

      parts = args.split()
      if len(parts) < 3:
        raise ValueError(registration_help_message)

      character_name = parts[0]
      class_name = ' '.join(parts[1:-1])
      password = parts[-1]

      # Strip leading 'the' from class name
      class_name = self.strip_leading_the(class_name)

      # Validate character_name and class_name (<=16 characters)
      is_valid, error_message = self.is_valid_name(character_name)
      if not is_valid:
        raise ValueError(f'Invalid character name: {error_message}')
      is_valid, error_message = self.is_valid_name(class_name, allow_spaces=True)
      if not is_valid:
        raise ValueError(f'Invalid class name: {error_message}')

      # Hash the password
      password_hash = self.ph.hash(password)

      # Check if the character name is already taken
      async with self.db.execute(
        'SELECT character_name FROM characters WHERE character_name = ?', (character_name,)
      ) as cursor:
        row = await cursor.fetchone()
        if row:
          raise ValueError(f'Character name {character_name} is already taken.')

      # Insert the new character into the database
      await self.db.execute(
        'INSERT INTO characters (character_name, class_name, password_hash, owner_nick, xp, level) VALUES (?, ?, ?, ?, ?, ?)',
        (character_name, class_name, password_hash, sender_nick, 0, 0),
      )
      await self.db.commit()

      # Send success message to the user
      success_message = (
        f'Registration successful! Your character {character_name}, the {class_name} has been created.\n'
        'The purpose of the game is to idle in the channel and level up your character. '
        'Talking, parting, quitting, and changing nicks have penalties.'
      )
      self.send_notice(sender_nick, success_message)

      # Calculate time until next level
      time_remaining = self.time_until_next_level(0, 0)
      time_formatted = self.format_time(time_remaining)

      # Announce in the channel
      channel_message = f"Welcome {sender_nick}'s new player: {character_name}, the {class_name}! Time until next level: {time_formatted}"
      self.send_channel_message(channel_message)

      print(f'User {sender_nick} registered character {character_name}, the {class_name}')
    except ValueError as e:
      # Send error message to the user
      error_message = str(e)
      self.send_notice(sender_nick, error_message)
      print(f'Registration failed for user {sender_nick}: {str(e)}')

  async def handle_unregister_command(self, sender_nick):
    """
    Handle the 'unregister' command sent by a user.

    Args:
        sender_nick (str): Nickname of the sender.
    """
    if self.db is None:
      raise RuntimeError('Database connection is not initialized')

    try:
      # Check if the user has registered
      async with self.db.execute(
        'SELECT character_name FROM characters WHERE owner_nick = ?', (sender_nick,)
      ) as cursor:
        row = await cursor.fetchone()
        if not row:
          raise ValueError('You have not registered a character.')

      character_name = row[0]

      # Delete the character from the database
      await self.db.execute('DELETE FROM characters WHERE owner_nick = ?', (sender_nick,))
      await self.db.commit()

      # Send success message to the user
      success_message = f'Your character {character_name} has been unregistered.'
      self.send_notice(sender_nick, success_message)

      # Announce in the channel
      channel_message = f'{sender_nick} has unregistered their character {character_name}.'
      self.send_channel_message(channel_message)

      print(f'User {sender_nick} unregistered character {character_name}')
    except ValueError as e:
      # Send error message to the user
      error_message = str(e)
      self.send_notice(sender_nick, error_message)
      print(f'Unregister failed for user {sender_nick}: {str(e)}')

  def is_valid_name(self, name, allow_spaces=False):
    """
    Validate a name to ensure it is <=16 characters (excluding spaces if allowed).

    Name can contain letters (accents, diacritics, CJK characters, etc.), numbers, dashes, and underscores.
    Class names may contain spaces.

    Args:
        name (str): The name to validate.
        allow_spaces (bool): Whether spaces are allowed in the name.

    Returns:
        Tuple[bool, str]: (is_valid, error_message) where is_valid is True if valid, False otherwise,
                          and error_message contains the reason if invalid.
    """
    name = name.strip()
    if not name:
      return False, 'Name cannot be empty.'

    # Allowed characters: letters, numbers, dashes, underscores, and optional spaces
    invalid_chars = []
    for c in name:
      if c == ' ' and allow_spaces:
        continue
      elif c.isalnum() or c in ('-', '_'):
        continue
      else:
        invalid_chars.append(c)

    if invalid_chars:
      invalid_chars_str = ''.join(sorted(set(invalid_chars)))
      return False, f"Name contains invalid characters: '{invalid_chars_str}'"

    # Count the number of characters (excluding spaces if allowed)
    char_count = len(name.replace(' ', '')) if allow_spaces else len(name)
    if char_count > 16:
      return False, f'Name must be at most 16 characters, but it has {char_count} characters.'
    return True, ''

  def strip_leading_the(self, s):
    """
    Strip leading 'the' from the class name.

    Args:
        s (str): The class name.

    Returns:
        str: Class name without leading 'the'.
    """
    s = s.strip()
    if s.lower().startswith('the '):
      return s[4:].strip()
    return s

  async def apply_penalty(self, nick, reason=''):
    """
    Apply penalty to the character associated with the given nick.

    Args:
        nick (str): Nickname of the user.
        reason (str): Reason for the penalty (e.g., 'TALK', 'PART', 'QUIT', 'NICK').
    """
    penalty_xp = self.xp_per_interval  # Define penalty amount (same as xp per interval)
    if self.db is None:
      raise RuntimeError('Database connection is not initialized')
    # Fetch the character associated with the nick
    async with self.db.execute(
      'SELECT character_name, class_name, xp, level FROM characters WHERE owner_nick = ?', (nick,)
    ) as cursor:
      row = await cursor.fetchone()
      if row:
        character_name, class_name, current_xp, current_level = row
        new_xp = max(current_xp - penalty_xp, 0)
        new_level = current_level
        leveled_down = False

        # Check for level-downs
        while new_level > 0 and new_xp < self.cumulative_xp[new_level]:
          new_level -= 1
          leveled_down = True
          print(f'{character_name} has leveled down to level {new_level}!')

        # Update character's XP and level
        await self.db.execute(
          'UPDATE characters SET xp = ?, level = ? WHERE character_name = ?', (new_xp, new_level, character_name)
        )
        await self.db.commit()

        if leveled_down:
          # Announce level-down in the channel
          time_remaining = self.time_until_next_level(new_level, new_xp)
          time_formatted = self.format_time(time_remaining)
          message = f"{nick}'s character {character_name} has dropped to level {new_level}. Time until next level: {time_formatted}"
          self.send_channel_message(message)

        # Map reason to 'reasoning' form
        reason_ing_map = {
          'PART': 'parting',
          'QUIT': 'quitting',
          'TALK': 'talking',
          'NICK': 'changing nick',
        }
        reason_text = reason_ing_map.get(reason.upper(), reason.lower() + 'ing')

        # Send the public penalty message
        public_message = f"{nick}'s character {character_name}, the {class_name}, has been penalized for {reason_text}."
        self.send_channel_message(public_message)

        # Notify the user about the penalty
        penalty_message = f'Your character {character_name}, the {class_name}, has been penalized for {reason_text}.'
        self.send_notice(nick, penalty_message)

  @staticmethod
  def parse_irc_line(line):
    """
    Parse a single line of IRC message.

    Args:
        line (str): The raw line.

    Returns:
        tuple: (prefix, command, params)
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
        str: Nickname.
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

      if self.db is None:
        raise RuntimeError('Database connection is not initialized')

      async with self.db.execute('BEGIN TRANSACTION;'):
        for user in self.users:
          # Fetch character associated with the user
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

              # Debug: Print current status
              print(
                f'User: {user}, Character: {character_name}, Class: {class_name}, Current XP: {current_xp}, Current Level: {current_level}'
              )

              # Check for level-ups
              while new_level + 1 < len(self.cumulative_xp) and new_xp >= self.cumulative_xp[new_level + 1]:
                new_level += 1
                leveled_up = True
                print(f"{user}'s {character_name} has leveled up to level {new_level}!")

              # Update character's XP and level
              await self.db.execute(
                'UPDATE characters SET xp = ?, level = ? WHERE character_name = ?', (new_xp, new_level, character_name)
              )

              if leveled_up:
                # Announce level-up in the channel
                time_remaining = self.time_until_next_level(new_level, new_xp)
                time_formatted = self.format_time(time_remaining)
                # Updated message to include the class name
                message = f"{user}'s character {character_name}, the {class_name}, has attained level {new_level}! Time until next level: {time_formatted}"
                self.send_channel_message(message)

        await self.db.commit()
        # Debug: Indicate that XP has been awarded
        print(f'Awarded {self.xp_per_interval} XP to characters.')

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
    if self.writer is None:
      raise RuntimeError('Writer is not initialized')
    # Send the message followed by the IRC message terminator '\r\n'
    self.writer.write(f'{message}\r\n'.encode('utf-8'))

  def send_channel_message(self, message):
    """
    Send a message to the channel.

    Args:
        message (str): The message to send.
    """
    self.send_raw(f'PRIVMSG {self.channel} :{message}')

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
    """
    # Get a custom quit message from the configuration, or use a default
    quit_message = self.config['irc'].get('quit_message', 'Goodbye!')
    try:
      # Send the QUIT command to the server
      self.send_raw(f'QUIT :{quit_message}')
      if self.writer is None:
        raise RuntimeError('Writer is not initialized')
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

  reconnect_attempts = 0
  MAX_RECONNECT_ATTEMPTS = 5
  RECONNECT_DELAY = 10  # seconds

  while reconnect_attempts <= MAX_RECONNECT_ATTEMPTS:
    try:
      await bot.connect()
      await bot.process_messages()
    except (KeyboardInterrupt, asyncio.CancelledError):
      # Handle user interrupt (Ctrl+C)
      print('Keyboard interrupt received. Exiting...')
      break
    except Exception as e:
      # Handle any other exceptions by attempting to reconnect
      reconnect_attempts += 1
      print(f'Error: {e}')
      if reconnect_attempts <= MAX_RECONNECT_ATTEMPTS:
        print(
          f'Attempting to reconnect in {RECONNECT_DELAY} seconds... (Attempt {reconnect_attempts}/{MAX_RECONNECT_ATTEMPTS})'
        )
        await asyncio.sleep(RECONNECT_DELAY)
      else:
        print('Max reconnect attempts reached. Exiting.')
        break
    finally:
      # Ensure the bot disconnects cleanly
      await bot.disconnect()
      # Re-initialize the bot
      bot = IdleZPGBot(config)

  print('Program terminated.')


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
