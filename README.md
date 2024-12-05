# IdleZPGBot

## Overview

IdleZPGBot is an IRCv3 bot designed to connect securely to an IRC server, authenticate using the SASL PLAIN mechanism,
and award experience points (XP) to users who are idling in the channel. It maintains user data, including XP and
levels, in an SQLite database.

## Features

- **Secure Connection**: Connects to IRC servers using SSL/TLS.
- **SASL Authentication**: Authenticates securely using the SASL PLAIN mechanism.
- **Experience System**: Awards XP to users periodically, tracks levels, and announces level-ups in the channel.
- **Database Integration**: Stores and manages user data in an SQLite database asynchronously.
- **Automatic User Management**: Automatically adds new users to the database when they join the channel.

## Usage Notes

- Ensure you have a `config.toml` file in the same directory with the appropriate configuration settings for the bot
to function correctly.
- The bot expects certain fields in the configuration file, such as server details, nickname, username, real name,
password, channel to join, and database configuration.
- Install the required dependencies before running the bot.

### Installing Dependencies

```shell
pip install aiosqlite toml
```

or

```shell
uv sync
```

### Running the Bot

```shell
python idlezpgbot.py
```

or

```shell
uv run idlezpgbot.py
```

## Configuration

The bot is configured using a `config.toml` file. Below is an example configuration with detailed explanations for
each section.

### Example `config.toml`

```toml
[irc]
server = "irc.example.net"          # IRC server address
port = 6697                         # IRC server port (usually 6697 for SSL)
nickname = "YourBotNick"            # Bot's nickname
username = "YourBotUser"            # Bot's username
realname = "Your Bot Real Name"     # Bot's real name
nickserv_password = "YourPassword"  # Password for SASL authentication
channel = "#yourchannel"            # IRC channel to join
quit_message = "Goodbye!"           # Message sent upon disconnect

[database]
path = "idlezpgbot.db"              # Path to the SQLite database file
```

### Configuration Sections

#### `[irc]` Section

- **server**: The address of the IRC server you want the bot to connect to.
- **port**: The port number for the IRC server. Typically, port `6697` is used for SSL/TLS connections.
- **nickname**: The nickname that the bot will use on the IRC server.
- **username**: The username for the bot. This is often the same as the nickname.
- **realname**: The real name of the bot, which is displayed in the IRC client.
- **nickserv_password**: The password for SASL authentication. Ensure this is kept secure.
- **channel**: The IRC channel that the bot will join upon connecting.
- **quit_message**: A custom message sent to the server when the bot disconnects.

#### `[database]` Section

- **path**: Specifies the file path for the SQLite database where user data (XP and levels) will be stored. Ensure
that the bot has read and write permissions for this path.

### Database Details

IdleZPGBot uses an SQLite database to store user data, allowing it to persist XP and level information across
restarts. The database is managed asynchronously using `aiosqlite`, ensuring non-blocking operations.

#### Database Schema

Upon initialization, the bot will create a `users` table if it doesn't already exist. The schema is as follows:

- **nickname** (`TEXT`, `PRIMARY KEY`): The IRC nickname of the user.
- **xp** (`INTEGER`, `NOT NULL`, `DEFAULT 0`): The accumulated experience points of the user.
- **level** (`INTEGER`, `NOT NULL`, `DEFAULT 0`): The current level of the user based on their XP.

If the `level` column is missing (from older versions), the bot will automatically add it to ensure compatibility.

#### User Management

- **Adding Users**: When a new user joins the channel, the bot checks if they exist in the database. If not, it adds
them with default XP and level values.
- **Awarding XP**: The bot periodically awards XP to all users currently in the channel. It also checks if users have
leveled up and announces it in the channel.
- **Level Up Announcements**: When a user reaches a new level, the bot announces the achievement and informs them of
the time remaining until the next level.

## Important Notes

- **Security**: The bot uses SASL PLAIN authentication over an SSL/TLS connection for secure communication. Ensure
that your `nickserv_password` is kept confidential.
- **Server Compatibility**: Ensure that the IRC server you are connecting to supports SASL authentication and that
your credentials are correct.
- **Database Persistence**: The SQLite database ensures that user data persists even if the bot restarts. Regular
backups are recommended to prevent data loss.
- **Bot Permissions**: The bot must have the necessary permissions to join the specified channel and send messages.
Ensure that the bot’s nickname is registered and has the appropriate access rights on the IRC server.

## Troubleshooting

- **Connection Issues**: Verify that the IRC server address and port are correct and that there are no network issues
preventing the bot from connecting.
- **Authentication Failures**: Ensure that the `nickserv_password` is correct and that the IRC server supports SASL
PLAIN authentication.
- **Database Errors**: Check that the specified database path is correct and that the bot has the necessary
permissions to read/write to the file.
- **Unexpected Behavior**: Review the console logs printed by the bot for any error messages or warnings that can help
identify the issue.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your enhancements or bug fixes.

## License

This project is licensed under the `GPL-3.0-or-later` License. See the [LICENSE](LICENSE) file for details.
