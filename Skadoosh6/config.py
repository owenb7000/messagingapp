# imports
import logging
import json
from pathlib import Path


# This class handles the storage and access of miscellaneous config within the app
class Config:
    """
    Manages config

    Provides properties to access and modify the config for the program
    """

    # Default values for the config
    DEFAULT_CONFIG = {
        'theme': 'System',
        'scaling': 1.0,
        "language": "English",
        'user_name': None,
        "password": None
    }

    def __init__(self, filename):
        """
        Initialize Config with a specified file.

        :param filename: The path to the config file.
        """
        self.logger = logging.getLogger(f"{__name__}.Config")  # Initialize logger for the class
        self.filename = Path(filename)  # Store the file path
        self._config_data = self.load_config()  # Load configuration data

    def load_config(self):
        """
        Load config data from the file.

        If the file doesn't exist, create a new one with default values.

        :return: The loaded config data.
        """
        self.logger.debug("Loading config.")
        try:
            with open(self.filename, 'r') as f:
                config_data = json.load(f)  # Load JSON data from file
                # Ensure 'user_name' is set in the config
                if 'user_name' not in config_data:
                    config_data['user_name'] = Config.DEFAULT_CONFIG['user_name']
                return config_data
        except FileNotFoundError:
            # If the config file doesn't exist, create a new one with default values
            with open(self.filename, 'w') as f:
                json.dump(Config.DEFAULT_CONFIG, f, indent=4)
            self.logger.warning("Config file not found. Created a new file with default values.")
            return Config.DEFAULT_CONFIG
        except json.decoder.JSONDecodeError as e:
            # Handle the case where the file has been corrupted/ contains incorrect JSON data
            self.logger.error(f"Error decoding JSON in config file: {e}")
            return Config.DEFAULT_CONFIG
        except Exception as e:
            # Handles unknown cases
            self.logger.exception(f"Error loading configuration: {e}")
            return Config.DEFAULT_CONFIG

    def save_config(self) -> None:
        """
        Save the current config data to the specified file.
        """
        self.logger.debug("Saving configuration.")
        try:
            with open(self.filename, 'w') as f:
                json.dump(self._config_data, f, indent=4)  # Dump JSON data to file
            self.logger.info("Configuration saved to file")
        except (PermissionError, Exception) as e:
            self.logger.exception(f"Error saving configuration: {e}")

    @property
    def theme(self) -> str:
        """Get the current theme."""
        return self._config_data.get('theme', Config.DEFAULT_CONFIG['theme'])

    @theme.setter
    def theme(self, value) -> None:
        """Set the theme and save it to config"""
        try:
            if value is not None:
                self._config_data['theme'] = value
                self.save_config()
                self.logger.info(f"Theme set to {value}")
        except Exception as e:
            self.logger.exception(f"Error setting theme: {e}")

    @property
    def scaling(self) -> str:
        """Get the current scaling setting."""
        return self._config_data.get('scaling', Config.DEFAULT_CONFIG['scaling'])

    @scaling.setter
    def scaling(self, value) -> None:
        """Set the scaling and save it to the config"""
        try:
            if value is not None:
                self._config_data['scaling'] = value
                self.save_config()
                self.logger.info(f"Scaling set to {value}")
        except Exception as e:
            self.logger.exception(f"Error setting scaling: {e}")

    @property
    def language(self) -> str:
        """Get the current language setting."""
        return self._config_data.get("language", Config.DEFAULT_CONFIG["language"])

    @language.setter
    def language(self, value) -> None:
        """Set the language and save it to the config"""
        try:
            if value is not None:
                self._config_data["language"] = value
                self.save_config()
                self.logger.info(f"Language set to {value}")
        except Exception as e:
            self.logger.exception(f"Error setting language: {e}")

    @property
    def user_name(self) -> str:
        """Get the current username."""
        return self._config_data.get('user_name', Config.DEFAULT_CONFIG['user_name'])

    @user_name.setter
    def user_name(self, value) -> None:
        """
        Set the username if it hasn't been set already and save it to the config.

        :param value: The new username.
        """
        self.logger.debug("Setting user name.")
        try:
            if self._config_data['user_name'] is None and value is not None:
                self._config_data['user_name'] = value
                self.save_config()
                self.logger.info(f"User name set to {value}")
            else:
                self.logger.warning("User name has already been set and cannot be changed.")
        except Exception as e:
            self.logger.exception(f"Error setting user name: {e}")

    @property
    def password(self) -> str:
        """Get the current password."""
        return self._config_data.get('password', Config.DEFAULT_CONFIG['password'])

    @password.setter
    def password(self, value) -> None:
        """
        Set the password if it hasn't been set already and save it to the config.

        :param value: The new password.
        """
        self.logger.debug("Setting password.")
        try:
            if self._config_data['password'] is None and value is not None:
                self._config_data['password'] = value
                self.save_config()
                self.logger.info("Password set")
            else:
                self.logger.warning("Password has already been set and cannot be changed.")
        except Exception as e:
            self.logger.exception(f"Error setting password: {e}")
