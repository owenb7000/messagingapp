from pathlib import Path
import logging

import networking
from contactsystem import Contact, ContactManager, ContactLoader
from messagehistory import StoredMessage, HistoryManager, HistoryLoader
from buffersystem import BufferLoader, BufferManager, BufferedMessage
from gui import GUI, get_username
from config import Config
from networking import Sender, Receiver, NetworkInfo
from keysystem import KeyManager
from encryptionmanager import EncryptionManager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from encryptionmanager import RSAPublicKey
import threading
from datetime import datetime
import time
import pickle

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("Skadoosh")

PORT = 4444


class MessageType(Enum):
    INTRO = "intro"
    INTRO_RESPONSE = "intro_response"

    STR_MESSAGE = "str_message"
    FILE_MESSAGE = "file_message"

    HELLO = "hello"
    BYE = "bye"
    MESSAGE_CONFIRMATION = "message_confirmation"

    BUFFER_ADD = "buffer_add"
    BUFFER_REMOVE = "buffer_remove"


@dataclass
class Message:
    type: MessageType
    content: Any
    signature: bytes = field(init=False)
    signature_key: bytes = field(init=False)
    encrypted: bool = field(init=False)
    encryption_key: Optional[RSAPublicKey] = field(default=None)

    def __post_init__(self) -> None:
        if self.encryption_key:
            self.content = EncryptionManager.encrypt(self.content, self.encryption_key)
            self.encryption_key = None
            self.encrypted = True
        else:
            self.encrypted = False
        self.signature = EncryptionManager.sign(self.content, key_manager.private_key)
        self.signature_key = key_manager.public_key_bytes


def handle_intro(message) -> None:
    logger.debug(f"Handling INTRO message: {message.content}")
    contact = message.content
    contact_manager.add_contact(contact)

    Bosh.send_intro_response(contact.ip)
    gui.update_contact_selector()
    gui.log(f"Added by {contact.name}")


def handle_intro_response(message) -> None:
    logger.debug(f"Handling INTRO_RESPONSE message: {message.content}")
    contact = message.content
    contact_manager.add_contact(contact)
    gui.update_contact_selector()
    gui.log(f"Added {contact.name}")


def handle_str_message(message) -> None:
    logger.debug(f"Handling STR_MESSAGE message: {message.content}")

    stored_message = message.content
    sent_by = contact_manager.get_contact_by_public_key(message.signature_key)

    history_manager.add_message(sent_by.name, stored_message)
    gui.update_message_display()
    gui.log(f"Message from {sent_by.name}")

    ip = sent_by.ip
    key = EncryptionManager.load_public_key(sent_by.public_key)

    message = Message(type=MessageType.MESSAGE_CONFIRMATION, content=stored_message.id, encryption_key=key)
    if not Sender.send(ip, PORT, message):
        buffer.add_message(BufferedMessage(internal=True, message=message, ip=ip))


def handle_file_message(message) -> None:
    logger.debug(f"Handling FILE_MESSAGE message: {message.content}")

    data = message.content[0]
    stored_message = message.content[1]

    sent_by = contact_manager.get_contact_by_public_key(message.signature_key)
    contact_media_folder = Path("media") / sent_by.name

    if not contact_media_folder.exists():
        contact_media_folder.mkdir(parents=True, exist_ok=True)

    new_file = Path("media") / sent_by.name / stored_message.content

    with open(new_file, "wb") as f:
        f.write(data)

    history_manager.add_message(sent_by.name, stored_message)
    gui.update_message_display()
    gui.log(f"File from {sent_by.name}")

    ip = sent_by.ip
    key = EncryptionManager.load_public_key(sent_by.public_key)

    message = Message(type=MessageType.MESSAGE_CONFIRMATION, content=stored_message.id, encryption_key=key)
    if not Sender.send(ip, PORT, message):
        buffer.add_message(BufferedMessage(internal=True, message=message, ip=ip))


def handle_hello(message) -> None:
    logger.debug(f"Handling HELLO message: {message.content}")
    sent_by = contact_manager.get_contact_by_public_key(message.signature_key)
    contact_manager.update_contact_ip(sent_by.name, message.content)
    gui.log(f"{sent_by.name} came online")


def handle_bye(message) -> None:
    logger.debug(f"Handling BYE message: {message.content}")
    sent_by = contact_manager.get_contact_by_public_key(message.signature_key)
    gui.log(f"{sent_by.name} went offline")


def handle_message_confirmation(message) -> None:
    logger.debug(f"Handling MESSAGE_CONFIRMATION message: {message.content}")
    history_manager.confirm(message.content)
    gui.update_message_display()


def handle_buffer_add(message) -> None:
    logger.debug(f"Handling BUFFER_ADD message: {message.content}")
    buffered_message = message.content
    buffered_message.internal = False
    buffer.add_message(buffered_message)


def handle_buffer_remove(message) -> None:
    logger.debug(f"Handling BUFFER_REMOVE message: {message.content}")


# maps message types to handlers
message_handlers = {
    MessageType.INTRO: handle_intro,
    MessageType.INTRO_RESPONSE: handle_intro_response,
    MessageType.STR_MESSAGE: handle_str_message,
    MessageType.FILE_MESSAGE: handle_file_message,
    MessageType.HELLO: handle_hello,
    MessageType.BYE: handle_bye,
    MessageType.MESSAGE_CONFIRMATION: handle_message_confirmation,
    MessageType.BUFFER_ADD: handle_buffer_add,
    MessageType.BUFFER_REMOVE: handle_buffer_remove,
}


class Bosh:
    @staticmethod
    def send_intro(ip: str) -> None:
        my_name = config.user_name
        my_ip = net_info.private_ipv4 if networking.is_private_ip(ip) else net_info.public_ipv4
        my_key = key_manager.public_key_bytes
        me = Contact(my_name, my_ip, my_key)
        message = Message(type=MessageType.INTRO, content=me)
        if not Sender.send(ip, PORT, message):
            buffer.add_message(BufferedMessage(internal=True, message=message, ip=ip))

    @staticmethod
    def send_intro_response(ip: str) -> None:
        my_name = config.user_name
        my_ip = net_info.private_ipv4 if networking.is_private_ip(ip) else net_info.public_ipv4
        my_key = key_manager.public_key_bytes
        me = Contact(my_name, my_ip, my_key)
        message = Message(type=MessageType.INTRO_RESPONSE, content=me)
        if not Sender.send(ip, PORT, message):
            buffer.add_message(BufferedMessage(internal=True, message=message, ip=ip))

    @staticmethod
    def send_str_message(contact_name: str, text: str) -> None:
        contact = contact_manager.get_contact_by_name(contact_name)
        ip = contact.ip

        if text.startswith("/c"):
            history_manager.clear_message_history(contact_name)
            gui.update_message_display()
            return

        key = EncryptionManager.load_public_key(contact.public_key)
        datetime = current_datetime()

        message_content = StoredMessage(content=text, date=datetime, type="string", sent_by_me=False)
        message = Message(type=MessageType.STR_MESSAGE, content=message_content, encryption_key=key)
        if not Sender.send(ip, PORT, message):
            buffer.add_message(BufferedMessage(internal=True, message=message, ip=ip))

        message_content = StoredMessage(content=text, date=datetime, type="string", sent_by_me=True)
        history_manager.add_message(contact.name, message_content)
        gui.update_message_display()

    @staticmethod
    def send_file_message(contact_name: str, file_path: Path) -> None:
        with open(file_path, "rb") as f:
            data = f.read()
            data = pickle.dumps(data)

        contact = contact_manager.get_contact_by_name(contact_name)
        ip = contact.ip
        key = EncryptionManager.load_public_key(contact.public_key)

        datetime = current_datetime()
        message_content = StoredMessage(content=file_path.name, date=datetime, type="string", sent_by_me=False)
        message = Message(type=MessageType.FILE_MESSAGE, content=[data, message_content], encryption_key=key)
        if not Sender.send(ip, PORT, message):
            buffer.add_message(BufferedMessage(internal=True, message=message, ip=ip))

        message_content = StoredMessage(content=file_path.name, date=datetime, type="string", sent_by_me=True)
        history_manager.add_message(contact.name, message_content)
        gui.update_message_display()

    @staticmethod
    def send_hello_message(contact: Contact, my_ip: str) -> None:
        key = EncryptionManager.load_public_key(contact.public_key)
        message = Message(type=MessageType.HELLO, content=my_ip, encryption_key=key)
        Sender.send(target_ip=contact.ip, port=PORT, object_to_send=message)

    @staticmethod
    def send_bye_message(contact: Contact) -> None:
        key = EncryptionManager.load_public_key(contact.public_key)
        message = Message(type=MessageType.BYE, content="bye", encryption_key=key)
        Sender.send(target_ip=contact.ip, port=PORT, object_to_send=message)



def process_packet(packet) -> None:
    message = packet.content

    key = EncryptionManager.load_public_key(message.signature_key)
    if EncryptionManager.verify(message.signature, message.content, key):
        if message.encrypted:
            message.content = EncryptionManager.decrypt(message.content, key_manager.private_key)
        message_handlers[message.type](message)


def current_datetime() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S")


def init_listener() -> None:
    time.sleep(2)
    listener = Receiver("0.0.0.0", 4444)
    listener.start(handler=process_packet)


def send_buffered_message(buffered_message: BufferedMessage) -> bool:
    """
    Attempt to send a buffered message in message buffer.

    If successful, remove the message from the buffer.

    Args:
        buffered_message (BufferedMessage): The message to be sent.

    Returns:
        bool: True if the message is sent successfully, False otherwise.
    """

    if Sender.send(buffered_message.ip, PORT, buffered_message.message):
        logging.info("Buffered message sent")
        buffer.remove_message(buffered_message)
        return True
    else:
        logging.error("failed to send buffer message")
        return False


def buffer_logic() -> None:
    """
    Logic for processing the failed message buffer
    """
    while True:
        messages = buffer.get_all_messages()

        if messages:
            # create list of threads to run, one for each message
            threads = []
            for message in messages:
                thread = threading.Thread(target=send_buffered_message, args=(message,))
                threads.append(thread)
                thread.start()

            # ait for all threads to complete
            for thread in threads:
                thread.join()

        else:
            # If no messages in the buffer, wait for a short duration before checking again
            time.sleep(1)

def startup_logic() -> None:
    for contact in contact_manager.contacts:
        if contact.name == config.user_name:
            continue
        if networking.is_private_ip(contact.ip):
            my_ip = net_info.private_ipv4
        else:
            my_ip = net_info.public_ipv4

        thread = threading.Thread(target=Bosh.send_hello_message, args=(contact, my_ip))
        thread.start()
def shutdown_logic() -> None:
    for contact in contact_manager.contacts:
        if not contact.name == config.user_name:
            for buffered_message in buffer.get_all_messages():
                if buffered_message.internal:
                    message = Message(type=MessageType.BUFFER_ADD, content=buffered_message)
                    thread = threading.Thread(target=Sender.send, args=(contact.ip, PORT, message))
                    thread.start()

    for contact in contact_manager.contacts:
        if contact.name == config.user_name:
            continue

        thread = threading.Thread(target=Bosh.send_bye_message, args=(contact,))
        thread.start()


if __name__ == "__main__":

    # creating data directory for storage of program data
    data_folder = Path("data")
    if not data_folder.exists():
        data_folder.mkdir(parents=True, exist_ok=True)

    # creating data directory for storage of program data
    media_folder = Path("media")
    if not media_folder.exists():
        media_folder.mkdir(parents=True, exist_ok=True)

    # initialisation of config
    config_file_path = data_folder / "config.json"
    config = Config(config_file_path)
    if not config.user_name:
        user_name = get_username()
        if user_name is not None:
            config.user_name = user_name
        else:
            quit("Enter username, or set manually in config")


    # provides info on ips
    net_info = NetworkInfo()

    # initialisation of key management system
    key_file_path = data_folder / "key.pem"
    key_manager = KeyManager(key_filename=key_file_path, password="test")

    # Initialization of contact system
    contact_file_path = data_folder / "contacts.pkl"
    contact_loader = ContactLoader(contact_file_path)
    contact_manager = ContactManager(loader=contact_loader)  # Use contact_loader here
    me = Contact(name=config.user_name, ip="127.0.0.1", public_key=key_manager.public_key_bytes)
    contact_manager.add_contact(me)

    # initialization of message history system
    history_file_path = data_folder / "message_history.json"
    history_loader = HistoryLoader(history_file_path)
    history_manager = HistoryManager(loader=history_loader)

    # initialisation of buffer system
    buffer_file_path = data_folder / "buffer.pkl"
    buffer_loader = BufferLoader(buffer_file_path)
    buffer = BufferManager(buffer_loader)

    buffer_thread = threading.Thread(target=buffer_logic, daemon=True)
    buffer_thread.start()

    listener_thread = threading.Thread(target=init_listener, daemon=True)
    listener_thread.start()

    startup_thread = threading.Thread(target=startup_logic)
    startup_thread.start()

    gui = GUI(config, contact_manager, history_manager, net_info, Bosh)
    gui.mainloop()

    shutdown_logic()

    exit()
