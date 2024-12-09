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
- **Penalties**: Applies penalties for talking, parting, quitting, and changing nicks.

## Usage Notes

- Ensure you have a `config.toml` file in the same directory with the appropriate configuration settings for the bot to
function correctly.
- The bot expects certain fields in the configuration file, such as server details, nickname, username, real name,
password, channel to join, and database configuration.
- Install the required dependencies before running the bot.

### Installing Dependencies

```shell
pip install aiosqlite toml argon2-cffi
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

The bot is configured using a `config.toml` file. Below is an example configuration with detailed explanations for each
section.

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
max_reconnect_attempts = 10         # Maximum number of reconnect attempts
reconnect_delay = 10                # Delay between reconnect attempts (in seconds)
read_timeout = 300                  # Read timeout in seconds

[database]
path = "idlezpgbot.db"              # Path to the SQLite database file

[game]
xp_interval = 60                    # Time interval in seconds to award XP
xp_per_interval = 10                # XP awarded per interval
max_level = 100                     # Maximum level for characters
precompute_base_time = 600          # Base time for initial level-up calculations
precompute_exponent = 1.16          # Exponent for level-up time scaling
additional_time_per_level = 86400   # Additional time per level after level 60 (in seconds)
refresh_interval = 60               # Refresh user list every X seconds
penalty_multiplier = 1.0            # Multiplier for penalty XP (penalty XP = xp_per_interval * penalty_multiplier)

[logging]
console_log_level = "INFO"          # Log level for console output (DEBUG, INFO, WARNING, ERROR, CRITICAL)
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
- **max_reconnect_attempts**: The maximum number of times the bot will attempt to reconnect to the server if the
connection is lost.
- **reconnect_delay**: The delay in seconds between reconnect attempts.
- **read_timeout**: The timeout in seconds for reading data from the server.

#### `[database]` Section

- **path**: Specifies the file path for the SQLite database where user data (XP and levels) will be stored. Ensure that
the bot has read and write permissions for this path.

#### `[game]` Section

- **xp_interval**: The time interval in seconds at which XP is awarded to users.
- **xp_per_interval**: The amount of XP awarded per interval.
- **max_level**: The maximum level that characters can reach.
- **precompute_base_time**: The base time for initial level-up calculations.
- **precompute_exponent**: The exponent used for scaling the time required to level up.
- **additional_time_per_level**: The additional time in seconds required per level after level 60.
- **refresh_interval**: The interval in seconds at which the user list is refreshed.
- **penalty_multiplier**: The multiplier applied to the XP penalty for actions such as talking, parting, quitting, and
changing nicks.

#### `[logging]` Section

- **console_log_level**: The log level for console output. Possible values are `DEBUG`, `INFO`, `WARNING`, `ERROR`, and
`CRITICAL`.

### Database Details

IdleZPGBot uses an SQLite database to store user data, allowing it to persist XP and level information across restarts.
The database is managed asynchronously using `aiosqlite`, ensuring non-blocking operations.

#### Database Schema

Upon initialization, the bot will create a `characters` table if it doesn't already exist. The schema is as follows:

- **character_name** (`TEXT`, `PRIMARY KEY`): The name of the character.
- **class_name** (`TEXT`, `NOT NULL`): The class of the character.
- **password_hash** (`TEXT`, `NOT NULL`): The hashed password for the character.
- **owner_nick** (`TEXT`, `NOT NULL`): The IRC nickname of the user who owns the character.
- **xp** (`INTEGER`, `NOT NULL`, `DEFAULT 0`): The accumulated experience points of the character.
- **level** (`INTEGER`, `NOT NULL`, `DEFAULT 0`): The current level of the character based on their XP.

#### User Management

- **Adding Users**: Users must register a character with the bot to participate. The bot checks if they exist in the
database and adds them if not.
- **Awarding XP**: The bot periodically awards XP to all users currently in the channel. It also checks if users have
leveled up and announces it in the channel.
- **Level Up Announcements**: When a user reaches a new level, the bot announces the achievement and informs them of
the time remaining until the next level.
- **Penalties**: The bot applies penalties for talking, parting, quitting, and changing nicks, which can result in XP
loss and level-downs.

### Commands

#### Register Command

Users must register a character with the bot to participate in the game. The registration command follows this format:

```irc
/msg <bot> register <character_name> <class_name> <password>
```

- **character_name**: The name of the character (must be <= 16 letters).
- **class_name**: The class of the character (must be <= 16 letters).
- **password**: A password to secure the character.

Example:

```irc
/msg IdleZPGBot register Gandalf Wizard mysecretpassword
```

#### Unregister Command

Users can unregister their character from the bot using the following command:

```irc
/msg <bot> unregister
```

This will remove the character associated with the user's nickname from the database.

## Logging

IdleZPGBot uses Python's `logging` module to log various events and messages. The logging configuration is set up to
log messages to different files and the console.

### Log Files

- **irc.log**: Logs all messages received from the IRC server.
- **privmsg.log**: Logs all private messages and channel messages sent by the bot.
- **bot.log**: Logs general bot activities, including connection status, errors, and other significant events.

### Console Logging

The log level for console output can be configured in the `config.toml` file under the `[logging]` section. The default
log level is `INFO`, but it can be set to any of the following levels: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.

## Important Notes

- **Security**: The bot uses SASL PLAIN authentication over an SSL/TLS connection for secure communication. Ensure that
your `nickserv_password` is kept confidential.
- **Server Compatibility**: Ensure that the IRC server you are connecting to supports SASL authentication and that your
credentials are correct.
- **Database Persistence**: The SQLite database ensures that user data persists even if the bot restarts. Regular
backups are recommended to prevent data loss.
- **Bot Permissions**: The bot must have the necessary permissions to join the specified channel and send messages.
Ensure that the bot’s nickname is registered and has the appropriate access rights on the IRC server.

## Troubleshooting

- **Connection Issues**: Verify that the IRC server address and port are correct and that there are no network issues
preventing the bot from connecting.
- **Authentication Failures**: Ensure that the `nickserv_password` is correct and that the IRC server supports SASL
PLAIN authentication.
- **Database Errors**: Check that the specified database path is correct and that the bot has the necessary permissions
to read/write to the file.
- **Unexpected Behavior**: Review the console logs printed by the bot for any error messages or warnings that can help
identify the issue.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your enhancements or bug fixes.

## License

This project is licensed under the `GPL-3.0-or-later` license. See the [LICENSE](LICENSE) file for details.
