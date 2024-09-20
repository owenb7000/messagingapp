import logging
from pathlib import Path
from dataclasses import dataclass
import pickle
from typing import List, Any

@dataclass
class BufferedMessage:
    """Represents a message stored withing the buffer, contains the message to be sent as well as the ip to send to"""
    internal: bool
    message: Any
    ip: str

class BufferLoader:
    """Loads and saves the buffer to a file. Acts as an interface between a BufferManager instance and the file"""

    def __init__(self, file_path: Path) -> None:
        """
        Initializes a BufferLoader instance.

        Args:
            file_path (str): The path to the file where the buffer is stored (or to be created)
        """
        self.logger = logging.getLogger(f"{__name__}.BufferLoader")
        self.file = Path(file_path)

    def load_buffer(self) -> List[BufferedMessage]:
        """
        Loads the buffer from the file.

        Returns:
            List[BufferedMessage]: The messagebuffer.
        """
        try:
            with open(self.file, 'rb') as f:
                buffer_data = pickle.load(f)  # Load data from file
                self.logger.debug("Message buffer loaded successfully.")
                return buffer_data
        except FileNotFoundError:
            self.logger.info(f"Message buffer file not found, creating a new one: {self.file}")
            return []  # Return an empty buffer if file not found
        except (PermissionError, IOError) as e:
            self.logger.error(f"Error loading message buffer: {e}")
            return []  # Return an empty buffer when theres an error
        except Exception as e:
            self.logger.error(f"Unknown error loading message buffer: {e}")
            return []  # Return an empty buffer in unknown cases

    def save_buffer(self, message_buffer: List[BufferedMessage]) -> None:
        """
        Saves the buffer to the file.

        Args:
            message_buffer (List[BufferedMessage]): The buffer to save.
        """
        try:
            with open(self.file, 'wb') as f:
                pickle.dump(message_buffer, f, protocol=pickle.HIGHEST_PROTOCOL)  # Save data to file
            self.logger.info("Message buffer saved successfully.")
        except (PermissionError, IOError) as e:
            self.logger.error(f"Error saving message buffer: {e}")
        except Exception as e:
            self.logger.error(f"Unknown error saving message buffer: {e}")


class BufferManager:
    """Manages the buffer, uses BufferLoader to interface with the file"""

    def __init__(self, loader: BufferLoader) -> None:
        """
        Initializes a BufferManager instance.

        Args:
            loader (BufferLoader): The loader instance to load and save the message buffer.
        """
        self.logger = logging.getLogger(f"{__name__}.BufferManager")
        self.loader = loader
        self.message_buffer = loader.load_buffer()  # Load data on init

    def save_buffer(self) -> None:
        """Saves the current buffer."""
        self.loader.save_buffer(self.message_buffer)  # Save current data

    def add_message(self, message: BufferedMessage) -> None:
        """
        Adds a message to the buffer.

        Args:
            message (BufferedMessage): The message to add to the buffer.
        """
        try:
            # Check for duplicates before adding
            if message not in self.message_buffer:
                self.message_buffer.append(message)  # Add message to buffer
                self.save_buffer()  # Save changes
                self.logger.info(f"Added message to the buffer: {message}")
            else:
                self.logger.warning(f"Duplicate message found in the buffer: {message}")
        except (PermissionError, IOError) as e:
            self.logger.error(f"Error adding message to the buffer: {e}")
        except Exception as e:
            self.logger.error(f"Unknown error adding message to the buffer: {e}")

    def get_all_messages(self) -> List[BufferedMessage]:
        """
        Gets all messages from the buffer.

        Returns:
            List[BufferedMessage]: All messages in the buffer.
        """
        return self.message_buffer

    def remove_message(self, message: BufferedMessage) -> None:
        """
        Removes a message from the buffer.

        Args:
            message (BufferedMessage): The message to remove from the buffer.
        """
        try:
            # Checks if message is in buffer
            if message in self.message_buffer:
                self.message_buffer.remove(message)  # Remove message from buffer
                self.save_buffer()  # Save changes
                self.logger.info(f"Removed message from the buffer: {message}")
            else:
                self.logger.warning(f"Message not found in the buffer: {message}")
        except (PermissionError, IOError) as e:
            self.logger.error(f"Error removing message from the buffer: {e}")
        except Exception as e:
            self.logger.error(f"Unknown error removing message from the buffer: {e}")
