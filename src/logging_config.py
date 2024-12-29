import logging

# Configure logging
irc_logger = logging.getLogger('irc')
privmsg_logger = logging.getLogger('privmsg')
bot_logger = logging.getLogger('bot')

# Set log levels for all loggers to DEBUG
irc_logger.setLevel(logging.DEBUG)
privmsg_logger.setLevel(logging.DEBUG)
bot_logger.setLevel(logging.DEBUG)

# Create file handlers for each logger
irc_file_handler = logging.FileHandler('irc.log', mode='a')
privmsg_file_handler = logging.FileHandler('privmsg.log', mode='a')
bot_file_handler = logging.FileHandler('bot.log', mode='a')

# Set log levels for file handlers to DEBUG
irc_file_handler.setLevel(logging.DEBUG)
privmsg_file_handler.setLevel(logging.DEBUG)
bot_file_handler.setLevel(logging.DEBUG)

# Create a console handler with a configurable log level
console_handler = logging.StreamHandler()
# Default level, can be configured
console_handler.setLevel(logging.INFO)

# Create a formatter and set it for all handlers
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
irc_file_handler.setFormatter(formatter)
privmsg_file_handler.setFormatter(formatter)
bot_file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the file handlers to the respective loggers
irc_logger.addHandler(irc_file_handler)
privmsg_logger.addHandler(privmsg_file_handler)
bot_logger.addHandler(bot_file_handler)

# Add the console handler to the bot logger (or any other logger if needed)
bot_logger.addHandler(console_handler)
