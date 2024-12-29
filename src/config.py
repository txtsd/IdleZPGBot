import toml


# Load configuration from 'config.toml' file.
def load_config():
    return toml.load('config.toml')
