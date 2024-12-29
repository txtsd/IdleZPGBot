import asyncio
import ssl

from bot import IdleZPGBot
from config import load_config
from logging_config import console_handler, bot_logger


async def run():
    """
    Load the configuration and run the IRC bot.

    Handles exceptions and ensures the bot disconnects properly upon termination.
    """
    # Load configuration from 'config.toml' file.
    config = load_config()

    # Set the console log level based on the configuration
    console_log_level = config['logging'].get('console_log_level', 'INFO').upper()
    console_handler.setLevel(console_log_level)

    # Instantiate the IRC bot with the loaded configuration.
    bot = IdleZPGBot(config)

    # Initialize reconnect settings.
    reconnect_attempts = 0
    MAX_RECONNECT_ATTEMPTS = config['irc']['max_reconnect_attempts']
    RECONNECT_DELAY = config['irc']['reconnect_delay']

    while reconnect_attempts <= MAX_RECONNECT_ATTEMPTS and not bot.shutdown:
        try:
            # Connect to the IRC server.
            await bot.connect()
            # Run process_messages as a separate task.
            bot.message_task = asyncio.create_task(bot.process_messages())
            await bot.message_task
        except KeyboardInterrupt:
            # Handle user interrupt (Ctrl+C).
            bot_logger.warning('Keyboard interrupt received. Exiting...')
            bot.shutdown = True
            break
        except Exception as e:
            if bot.shutdown:
                bot_logger.info('Bot is shutting down.')
                break
            # Handle any other exceptions by attempting to reconnect.
            reconnect_attempts += 1
            bot_logger.error(f'Error: {e}')
            if reconnect_attempts <= MAX_RECONNECT_ATTEMPTS:
                bot_logger.info(
                    f'Attempting to reconnect in {RECONNECT_DELAY} seconds... (Attempt {reconnect_attempts}/{MAX_RECONNECT_ATTEMPTS})'
                )
                await asyncio.sleep(RECONNECT_DELAY)
            else:
                bot_logger.error('Max reconnect attempts reached. Exiting.')
                break
        finally:
            # Ensure the bot disconnects cleanly.
            await bot.disconnect()
            # Re-initialize the bot (if not shutting down).
            if not bot.shutdown:
                bot = IdleZPGBot(config)

    bot_logger.info('Program terminated.')


def main():
    """
    Entry point for the program.

    Runs the asyncio event loop and handles keyboard interrupts.
    """
    try:
        asyncio.run(run())
    except ssl.SSLError:
        pass
    except KeyboardInterrupt:
        bot_logger.info('Program terminated.')
    except Exception as e:
        bot_logger.error(f'Unhandled exception in main: {e}', exc_info=True)


if __name__ == '__main__':
    main()
