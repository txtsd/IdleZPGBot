import asyncio
import ssl
import toml
import base64
import aiosqlite


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
        self.xp_task = None  # Background task for awarding XP
        self.db = None  # Database connection

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
                xp INTEGER NOT NULL DEFAULT 0
            )
        """)
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
                            self.users.add(user)
                            await self.ensure_user_in_db(user)

                    # Handle JOIN messages
                    elif 'JOIN' in line:
                        prefix = line.split('!', 1)[0][1:]
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
        async with self.db.execute("SELECT xp FROM users WHERE nickname = ?", (nickname,)) as cursor:
            row = await cursor.fetchone()
            if row is None:
                # User not in database, insert them
                await self.db.execute("INSERT INTO users (nickname, xp) VALUES (?, ?)", (nickname, 0))
                await self.db.commit()
                print(f'Added new user to database: {nickname}')

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
                    await self.db.execute(
                        "UPDATE users SET xp = xp + ? WHERE nickname = ?",
                        (self.xp_per_interval, user)
                    )
                await self.db.commit()
            print(f'Awarded {self.xp_per_interval} XP to users: {", ".join(self.users)}')

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
        # Ensure the message is sent without blocking the event loop
        asyncio.create_task(self.writer.drain())

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
