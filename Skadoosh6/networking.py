"""
Networking Module

This module provides classes for sending and receiving data over a TCP connection using sockets.
It includes a Sender class for sending data and a Receiver class for receiving data.
The module also defines a Packet data class to encapsulate the content and source IP of received data.

Classes:
    - Sender: A class for sending data to a specified IP and port.
    - Receiver: A class for receiving data on a specified IP and port.
    - Packet: Data class to represent a packet containing content and source IP.

Functions:
    - is_valid_ip: Checks if a given string is a valid IP address.
    - is_valid_port: Checks if a given integer is a valid port number.

Usage Example:
    (Sending side)
        if Sender.send("192.168.1.5", 4444, "hello"):
            print("Successfully sent!")

    (Receiving side)
        def handler(data):
            print(data.content)

        listener = Receiver("0.0.0.0", 4444)
        listener.start(handler)
"""

# Imports
import socket
import struct
import pickle
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional
import ipaddress
import threading
import requests


@dataclass
class Packet:
    content: Any
    ip: str


class InvalidIP(Exception):
    pass


class InvalidPort(Exception):
    pass


class InvalidObject(Exception):
    pass


class Sender:
    def __enter__(self) -> "Sender":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.socket.close()

    def __init__(self, socket_timeout=3) -> None:

        self.logger = logging.getLogger(f"{__name__}.Sender")  # Sets logger for class

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Creates a TCP IPv4 socket object
        self.socket.settimeout(socket_timeout)  # Sets the socket timeout (default is 3 seconds)

        # Class constants
        self.header_format = "<I"  # Sets the format of headers to a 4 byte unsigned int (little endian)
        self.acknowledgment_byte = b"\x01"  # Arbitrary value used to acknowledging messages

    def send_data(self, host, port, message) -> bool:
        """Internal method, use send() instead."""

        try:
            self.logger.debug(f"Sending data to {host}:{port}")

            serialised_message = pickle.dumps(message)  # Serialise data into bytes
            # Creates a header that indicates the length of the data to be sent
            header = struct.pack(self.header_format, len(serialised_message))
            data = header + serialised_message  # Concatenates header and data

            # Attempts to connect to given ip:port
            self.socket.connect((host, port))

            # Sends the data to this port
            self.socket.sendall(data)

            # Waits to receive acknowledgment
            acknowledgement = self.socket.recv(1)

            # If acknowledgment is received, data was definitely sent. Return result of this check
            return acknowledgement == self.acknowledgment_byte

        # In case where the data to send was not serializable
        except pickle.PicklingError as e:
            self.logger.error(f"Error pickling object: {e}")
            raise InvalidObject(f"{message}")

        # In case where time to receive ack > socket timeout, assume message was not received
        except socket.timeout:
            self.logger.error(f"Timeout while sending message to {host}:{port}")
            return False

        # In case of OS related errors, usually refused connection by target socket.
        except (socket.error, OSError) as e:
            self.logger.error(f"Error while sending message to {host}:{port}: {e}")
            return False

        # Cleanup
        finally:
            self.logger.debug("Closing socket.")
            self.socket.close()

    @staticmethod
    def send(target_ip: str, port: int, object_to_send: Any) -> bool:
        """

        :param target_ip: IP of target device.
        :param port: Port that target device is listening on.
        :param object_to_send: Data to be sent.
        :return: True if message was definitely sent, False otherwise.
        """
        # Checks provided IP is valid
        if not is_valid_ip(target_ip):
            raise InvalidIP(f"{target_ip}")

        # Checks provided port is valid
        if not is_valid_port(port):
            raise InvalidPort(f"{port}")

        # Calls send_data() method, passing through the output
        # Uses context manager to ensure no issues with duplicate sockets or address re-use
        with Sender() as sender:
            return sender.send_data(target_ip, port, object_to_send)


class Receiver:

    def __init__(self, host: str, port: int) -> None:

        self.logger = logging.getLogger(f"{__name__}.Receiver")  # Sets logger for class

        # Checks provided IP is valid
        if not is_valid_ip(host):
            self.logger.error(f"Invalid IP address: {host}")
            raise InvalidIP(host)

        # Checks provided port is valid
        if not is_valid_port(port):
            self.logger.error(f"Invalid port number: {port}")
            raise InvalidPort(port)

        self.host = host
        self.port = port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Creates TCP IPv4 socket
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Sets to allow re-binding to addresses
        self.socket.bind((self.host, self.port))  # Binds socket to the provided ip:port
        self.socket.listen(1)  # Sets to allow one connection at a time

        # Class constants
        self.header_format = "<I"  # Sets the format of headers to a 4 byte unsigned int (little endian)
        self.acknowledgement_byte = b"\x01"  # Arbitrary value used to acknowledging messages
        self.data_buffer = []  # Creates a list to act as a buffer for connections

        self.socket.settimeout(1)  # sets timeout of socket to 1 second, has no effect on actual function

    def __del__(self) -> None:
        self.logger.debug("Cleanup")

        # ensures sockets are closed in case of errors
        if hasattr(self, 'socket') and self.socket:
            self.socket.close()

    def receive_data(self) -> None:
        try:
            conn, addr = self.socket.accept()  # accepts incoming connections
            self.logger.debug(f"Accepted connection from {addr}")

            with conn:
                header = conn.recv(4)  # received header of data
                length = struct.unpack(self.header_format, header)[0]  # Determines length of data from the header

                received_data = b""  # Empty bytes to append data onto

                # Receives until the length of the data matches the length from the header
                while len(received_data) < length:
                    chunk = conn.recv(length - len(received_data))
                    if not chunk:
                        break
                    received_data += chunk

                if received_data:
                    content, source_ip = pickle.loads(received_data), addr[0]  # Loads bytes back into object
                    received_packet = Packet(content, source_ip)  # represents the received data as a 'packet' also
                    # containing the IP
                    self.data_buffer.append(received_packet)  # Appends complete received object onto buffer
                    conn.sendall(self.acknowledgement_byte)  # Sends acknowledgment byte

        # For when idling, no incoming connections
        except socket.timeout:
            pass

        # In case of actual errors with socket
        except (socket.error, OSError) as e:
            self.logger.error(f"Error: {e}")

    def get_data(self) -> Optional[Packet]:
        if self.data_buffer:
            return self.data_buffer.pop(0)
        return None

    def start(self, handler: Callable) -> None:
        """
        Starts process of continuously listening for connections, and running the passed function when data is received.

        :param handler: Function used to process the received data.
        """

        while True:

            # attempts to receive data
            try:
                self.receive_data()
            except socket.timeout:
                pass

            # Retrieves data from buffer
            data = self.get_data()

            # In case there is data, runs function with data as argument
            if data:
                task = threading.Thread(target=handler, args=(data,)) # Runs as thread so separate from listening logic
                task.start()


class NetworkInfo:

    def __init__(self):
        """
        Initialize NetworkInfo and fetch the information.
        """
        self.logger = logging.getLogger(f"{__name__}.NetworkInfo")
        self._public_ipv4 = self.get_public_ipv4_address()
        self._private_ipv4 = self.get_private_ipv4_address()
        self._ipv6 = self.get_ipv6_address()

    @property
    def public_ipv4(self):
        """
        Get the public IPv4 address.

        :return: Public IPv4 address.
        """
        return self._public_ipv4

    @property
    def private_ipv4(self):
        """
        Get the private IPv4 address.

        :return: Private IPv4 address.
        """
        return self._private_ipv4

    @property
    def ipv6(self):
        """
        Get the IPv6 address.

        :return: IPv6 address.
        """
        return self._ipv6

    def get_public_ipv4_address(self):
        """
        Fetch the public IPv4 address using an external service.

        :return: Public IPv4 address or None if unable to fetch.
        """
        try:
            response = requests.get("https://api64.ipify.org?format=json")
            response.raise_for_status()  # For errors in API
            public_ipv4_address = response.json()["ip"]
            self.logger.debug(f"Fetched public IPv4: {public_ipv4_address}")
            return public_ipv4_address
        except requests.RequestException as e:
            self.logger.error(f"Error fetching public IPv4: {e}")
            return None

    def get_private_ipv4_address(self):
        """
        Fetch the private IPv4 address.

        :return: Private IPv4 address or None if unable to fetch.
        """
        s = None

        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Get the priv IPv4
            private_ipv4_address = socket.gethostbyname(socket.gethostname())
            self.logger.debug(f"Fetched private IPv4: {private_ipv4_address}")
            return private_ipv4_address
        except socket.error as e:
            self.logger.error(f"Error fetching private IPv4: {e}")
            return None
        finally:
            # Close the socket
            if s:
                s.close()

    def get_ipv6_address(self):
        """
        Fetch the IPv6 address.

        :return: IPv6 address or None if unable to fetch.
        """
        s = None

        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

            # Connect to any remote IP
            s.connect(("ipv6.google.com", 80))

            # Get the IPv6
            ipv6_address = s.getsockname()[0]
            self.logger.debug(f"Fetched IPv6: {ipv6_address}")
            return ipv6_address
        except socket.error as e:
            self.logger.warning(f"Error fetching IPv6: {e}")
            return None
        finally:
            # Close the socket
            if s:
                s.close()


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_port(port: int) -> bool:
    try:
        port = int(port)
        return 0 < port <= 65535
    except ValueError:
        return False


def is_private_ip(ip):
    """
    Check if the given IP address is a private IP address.

    :param ip: The IP address to check.
    :return: True if the IP address is private, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(ip)
        return ip.is_private
    except ValueError:
        return False
