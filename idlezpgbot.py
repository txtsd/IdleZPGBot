import asyncio
import ssl
import toml
import base64


class IdleZPGBot:
    """
    An IRCv3 bot that connects to an IRC server using SSL/TLS, authenticates using
    SASL PLAIN mechanism, and joins a specified channel.
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

    async def process_messages(self):
        """
        Main loop to process incoming messages from the IRC server.

        Handles PING/PONG keep-alive messages, manages SASL authentication steps,
        and joins the specified channel after successful login.
        """
        # Extract required credentials from configuration
        nickname = self.config['irc']['nickname']
        password = self.config['irc']['nickserv_password']

        while True:
            try:
                # Read data from the server
                data = await self.reader.read(1024)
                if not data:
                    # No data indicates the server has closed the connection
                    break

                # Decode the received data to a string
                message = data.decode('utf-8').strip()
                print(f'{message}')

                # Respond to server PING messages to keep the connection alive
                if message.startswith('PING'):
                    self.send_raw(f'PONG {message[5:]}')

                # Handle server acknowledgment of SASL capability
                elif 'CAP * ACK :sasl' in message:
                    # Begin SASL authentication process
                    self.send_raw('AUTHENTICATE PLAIN')

                # Server prompts for authentication credentials
                elif 'AUTHENTICATE +' in message:
                    # Prepare credentials in the format: \0username\0password
                    credentials = f'\0{nickname}\0{password}'.encode('utf-8')
                    # Encode credentials in Base64 as required by SASL PLAIN mechanism
                    auth_message = base64.b64encode(credentials).decode('utf-8')
                    self.send_raw(f'AUTHENTICATE {auth_message}')

                # SASL authentication was successful
                elif '903' in message:
                    print('SASL authentication successful')
                    # End capability negotiation
                    self.send_raw('CAP END')

                # SASL authentication failed
                elif '904' in message or '905' in message:
                    print('SASL authentication failed')
                    return  # Exit the loop and disconnect

                # Server has sent the Message of the Day (MOTD), indicating login is complete
                elif 'MOTD' in message:
                    print('MOTD received')
                    # Proceed to join the specified channel
                    await self.join_channel()

            except asyncio.CancelledError:
                # Handle task cancellation gracefully
                print('Task cancelled during message processing.')
                break

    async def join_channel(self):
        """
        Join the channel specified in the configuration.

        Should be called after successfully connecting and authenticating with the server.
        """
        channel = self.config['irc']['channel']
        self.send_raw(f'JOIN {channel}')
        print(f'Joining channel: {channel}')

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
                # Close the writer stream to terminate the connection
                self.writer.close()
                await self.writer.wait_closed()
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
