
import pickle  # for serializing and deserializing objects
from pathlib import Path  # for handling file paths
from dataclasses import dataclass, field  # for creating data classes
import hashlib  # for hashing data
import logging  # for logging


@dataclass
class Contact:
    """Represents a contact with name, IP, and public key."""
    name: str  # Name of the contact
    ip: str  # IP address of the contact
    public_key: bytes  # Public key of the contact
    hash: str = field(init=False)  # Hash value of the contact's name for one way lookups

    def __post_init__(self) -> None:
        """Calculate hash of the contact's name."""
        self.hash = hashlib.sha256(self.name.encode('utf-8')).hexdigest()


class ContactNotFoundError(Exception):
    """Raised when a contact is not found."""
    pass


class ContactLoader:
    """Loads and saves contacts from/to a file."""

    def __init__(self, file_path) -> None:
        """
        Initialize ContactLoader with a specified file.

        :param file_path: The path to the contacts file.
        """
        self.filename = Path(file_path)  # The file path
        self.logger = logging.getLogger(f"{__name__}.ContactLoader")  # Initialize logger for the class

    def load_contacts(self) -> list:
        """Load contacts from the file."""
        try:
            with open(self.filename, 'rb') as f:
                contacts_data = pickle.load(f) # Loads data from file
            return [Contact(**data) for data in contacts_data] # Unpacks data and turns it into a list of Contacts
        except (FileNotFoundError, pickle.UnpicklingError):
            return []  # Return empty list if file not found or error with pickle

    def save_contacts(self, contacts: list) -> None:
        """Save contacts to the file."""
        contacts_data = [{'name': contact.name, 'ip': contact.ip, 'public_key': contact.public_key} for contact in
                         contacts] # Converts into a list of dictionaries containing the data, ready to be pickled
        with open(self.filename, 'wb') as f:
            pickle.dump(contacts_data, f, protocol=pickle.HIGHEST_PROTOCOL) # saved date to file


class ContactManager:
    """Manages contacts."""

    def __init__(self, loader: ContactLoader) -> None:
        """
        Initialize ContactManager.

        :param loader: The loader instance to load and save contacts.
        """
        self.contacts = loader.load_contacts()  # Load contacts on initialization
        self.contact_loader = loader  # Store the contact loader instance
        self.logger = logging.getLogger(__name__)  # Initialize logger

    def get_contact_by_name(self, name: str) -> Contact:
        """
        Get a contact by name.

        :param name: The name of the contact to retreive.
        :return: The contact object.
        """
        try:
            contact = next((contact for contact in self.contacts if contact.name == name)) # Iterates through
            # contacts until it finds a match
            self.logger.debug(f"Contact found by name: {name}")
            return contact
        except StopIteration:
            # Case where no match was found during iteration
            self.logger.debug(f"Contact not found by name: {name}")
            raise ContactNotFoundError(f"Contact not found by name: {name}")
        except Exception as e:
            # For unknown cases
            self.logger.error(f"Error getting contact by name: {e}")
            return None

    def get_contact_by_public_key(self, public_key: bytes) -> Contact:
        """
        Get a contact by public key.

        :param public_key: The public key of the contact to retrieve.
        :return: The contact object.
        """
        try:
            # Iterates through contacts until match is found
            contact = next((contact for contact in self.contacts if contact.public_key == public_key), None)
            if contact:
                self.logger.debug(f"Contact found: {public_key}")
            else:
                self.logger.debug(f"Contact not found: {public_key}")
            return contact
        except Exception as e:
            # For unknown cases
            self.logger.error(f"Error getting contact: {e}")
            return None

    def add_contact(self, contact: Contact) -> None:
        """
        Add a contact.

        :param contact: The contact to add.
        """
        try:
            # Checks for match, updates instead of adds if match is found
            existing_contact = next((c for c in self.contacts if c.name == contact.name), None)
            if existing_contact:
                existing_contact.ip = contact.ip
                existing_contact.public_key = contact.public_key
                self.logger.debug(f"Updated {contact.name}")
            else:
                self.contacts.append(contact)
                self.logger.debug(f"Added new: {contact.name}")
            self.contact_loader.save_contacts(self.contacts)
        except Exception as e:
            # Unknown cases
            self.logger.error(f"Error adding : {e}")

    def get_contact_by_hash(self, contact_hash: str) -> Contact:
        """
        Get a contact by hash.

        :param contact_hash: The hash of the contact's name.
        :return: The contact object.
        """
        try:
            # iterates through looking for match
            contact = next((contact for contact in self.contacts if contact.hash == contact_hash), None)
            if contact:
                self.logger.debug(f"Contact found: {contact_hash}")
            else:
                self.logger.debug(f"Contact not found: {contact_hash}")
            return contact
        except Exception as e:
            # Unknown cases
            self.logger.error(f"Error getting contact by hash: {e}")
            return None

    def get_contact_names(self) -> list[str]:
        """Get names of all contacts."""
        try:
            names = [contact.name for contact in self.contacts] # Creates list of names from contact list
            self.logger.debug(f"Got names: {names}")
            return names
        except Exception as e:
            self.logger.error(f"Error getting names: {e}")
            return []

    def update_contact_ip(self, name: str, new_ip: str) -> None:
        """
        Update IP address of a contact.

        :param name: The name of the contact.
        :param new_ip: The new IP address.
        """
        try:
            contact = self.get_contact_by_name(name)
            if contact:
                contact.ip = new_ip
                self.contact_loader.save_contacts(self.contacts)
                self.logger.debug(f"Updated IP for contact {name} to {new_ip}")
            else:
                self.logger.warning(f"{name} not found.")
        except Exception as e:
            self.logger.error(f"Error updating contact {e}")
