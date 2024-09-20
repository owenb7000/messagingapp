# imports
import logging
from pathlib import Path
import pickle
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from encryptionmanager import EncryptionManager

@dataclass(order=False)
class StoredMessage:
    content: str
    date: str
    type: Optional[str]
    sent_by_me: bool
    confirmed: bool = False
    id: str = field(init=False)

    def __post_init__(self):
        self.id = EncryptionManager.hash(self.content + self.date) # sets ID of message


    # methods to allow sorting messages via the date
    def __lt__(self, other):
        return self.date < other.date

    def __eq__(self, other):
        return self.date == other.date

    def __le__(self, other):
        return self.date <= other.date

    def __gt__(self, other):
        return self.date > other.date

    def __ge__(self, other):
        return self.date >= other.date


class HistoryLoader:

    def __init__(self, file_path) -> None:
        self.file = Path(file_path)
        self.logger = logging.getLogger(f"{__name__}.HistoryLoader")
        self.create_file_if_not_exists()

    def create_file_if_not_exists(self) -> None:
        if not self.file.exists():
            self.logger.info(f"Creating history file: {self.file}")
            with open(self.file, 'wb') as f:
                pickle.dump({}, f)

    def load_history(self) -> dict:
        try:
            self.logger.debug("Loading history.")
            with open(self.file, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            self.logger.warning("history file not found.")
            return {}
        except Exception as e:
            self.logger.error(f"Error loading: {e}")
            return {}

    def save_history(self, message_history: dict) -> None:
        try:
            self.logger.debug("Saving history.")
            with open(self.file, 'wb') as f:
                pickle.dump(message_history, f, protocol=pickle.HIGHEST_PROTOCOL)
            self.logger.info("saved successfully.")
        except Exception as e:
            self.logger.error(f"Error: {e}")


class HistoryManager:

    def __init__(self, loader: HistoryLoader) -> None:
        self.logger = logging.getLogger(f"{__name__}.HistoryManager")
        self.logger.setLevel(logging.DEBUG)
        self.loader = loader
        self.message_history = loader.load_history()

    def save_history(self) -> None:
        self.loader.save_history(self.message_history)

    def get_messages(self, contact_name: str) -> List[StoredMessage]:
        try:
            self.logger.debug(f"Getting messages for: {contact_name}")
            return self.message_history.get(contact_name, [])
        except Exception as e:
            self.logger.error(f"Error: {e}")
            return []

    def add_message(self, contact_name: str, message: StoredMessage) -> bool:
        try:
            self.logger.debug(f"Adding message for: {contact_name}")

            if not (contact_name and isinstance(contact_name, str)):
                raise ValueError("Invalid contac.")

            self.message_history.setdefault(contact_name, [])

            # Check for duplicates
            # Iterates through all messages, looks for match to current message
            existing_messages = self.message_history[contact_name]
            if any(((msg.id == message.id) and (msg.sent_by_me == message.sent_by_me)) for msg in existing_messages):
                self.logger.debug(f'Duplicate message: {contact_name}: {message.content} at {message.date}')
                return False

            # Insert the new message (in order of date)
            self.message_history[contact_name].append(message)
            self.message_history[contact_name] = sorted(self.message_history[contact_name], key=lambda x: x.date)
            self.save_history()
            return True

        except ValueError as ve:
            self.logger.error(f"Invalid parameter: {ve}")
        except Exception as e:
            self.logger.error(f"Error adding message: {e}")

    def clear_message_history(self, contact_name: str) -> None:
        try:
            self.logger.debug(f"Clearing: {contact_name}")
            if contact_name in self.message_history:
                del self.message_history[contact_name]
                self.logger.info(f"Cleared {contact_name}.")
                self.save_history()
        except Exception as e:
            self.logger.error(f"Error: {e}")

    def confirm(self, message_id: str) -> None:
        try:
            for contact_name, messages in self.message_history.items():
                for message in messages:
                    if message_id == message.id:
                        message.confirmed = True

                        self.logger.info(f"Confirmed: {message_id}")
                        self.save_history()
                        return
        except Exception as e:
            self.logger.error(f"Error: {e}")