import aiosqlite


async def initialize_database(bot):
    """
    Initialize the SQLite database and create the characters table if it doesn't exist.

    This method establishes a connection to the SQLite database file specified in the configuration,
    and ensures that the required table for storing character data exists.
    """
    db_name = bot.config['database']['path']

    # Connect to the SQLite database asynchronously.
    bot.db = await aiosqlite.connect(db_name)

    # Create the characters table if it doesn't already exist.
    await bot.db.execute(
        """
        CREATE TABLE IF NOT EXISTS characters (
            character_name TEXT PRIMARY KEY,
            class_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            owner_nick TEXT NOT NULL,
            xp INTEGER NOT NULL DEFAULT 0,
            level INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    # Create the items table for storing character items.
    await bot.db.execute(
        """
        CREATE TABLE IF NOT EXISTS items (
            character_name TEXT NOT NULL,
            item_type TEXT NOT NULL,
            item_level INTEGER NOT NULL,
            PRIMARY KEY (character_name, item_type),
            FOREIGN KEY (character_name) REFERENCES characters(character_name)
        )
        """
    )

    # Commit the changes to the database.
    await bot.db.commit()
