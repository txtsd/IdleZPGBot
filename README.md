# IdleZPGBot

## Usage Notes

- Ensure you have a `config.toml` file in the same directory with the
  appropriate configuration settings for the bot to function correctly.
- The bot expects certain fields in the configuration file, such as server
  details, nickname, username, real name, password, and the channel to join.

```shell
uv sync
uv run idlezpgbot.py
```

## Example `config.toml`

```toml
[irc]
server = "irc.example.net"
port = 6697
nickname = "YourBotNick"
username = "YourBotUser"
realname = "Your Bot Real Name"
nickserv_password = "YourPassword"
channel = "#yourchannel"
quit_message = "Goodbye!"
```

## Note

- This bot uses SASL PLAIN authentication over an SSL/TLS connection for
  security.
- Ensure that the server you are connecting to supports SASL authentication and
  that your credentials are correct.
