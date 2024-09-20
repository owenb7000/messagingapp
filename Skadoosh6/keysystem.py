# imports
import os
import logging
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

class KeyManager:
    """
    Manages the user's keys
    """

    def __init__(self, password, key_filename="private_key.pem") -> None:
        """
        Initialize the KeyManager.

        Args:
            password (str): The password for encrypting and decrypting the key.
            key_filename (Path): The path to the key file. Defaults to data/private_key.pem.
        """
        self.logger = logging.getLogger(f"{__name__}.KeyManager")  # Set up logger for KeyManager
        self.logger.debug(f"Initializing KeyManager with key filename: {key_filename}")
        self._key_filename = key_filename
        self._password = password
        self._private_key = self.load_or_generate_private_key() # sets private key using the load/gen function

    @property
    def private_key(self) -> RSAPrivateKey:
        """
        Get the private key.

        Returns:
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey: The private key.
        """
        self.logger.debug("Getting private key")
        return self._private_key

    @property
    def public_key(self) -> RSAPublicKey:
        """
        Get the public key derived from the private key.

        Returns:
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey: The public key.
        """
        self.logger.debug("Getting public key")
        if self._private_key:
            return self._private_key.public_key()
        else:
            # in case of error
            self.logger.error("Error extracting public key")
            return None

    @property
    def public_key_bytes(self) -> bytes:
        """
        Get the public key in the form of bytes.

        Returns:
            bytes: The public key bytes.
        """
        self.logger.debug("Getting public key bytes")
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @property
    def key_filename(self) -> str:
        """
        Get the key filename.

        Returns:
            Path: The key filename.
        """
        self.logger.debug("Getting key filename")
        return self._key_filename

    def load_or_generate_private_key(self) -> RSAPrivateKey:
        """
        Loads the key file or creates new if one does not exist

        Returns:
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey: Private key.
        """
        self.logger.debug("Loading or generating private key")
        try:
            if os.path.exists(self.key_filename):
                self.logger.debug("Private key file exists, loading from file")

                # opens file and loads key data
                with open(self.key_filename, 'rb') as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=self._password.encode('utf-8'),
                        backend=default_backend()
                    )
                self.logger.info("Private key loaded successfully.")
            else:
                self.logger.debug("Private key file does not exist, generating new key")
                private_key = self.generate_private_key()

        except FileNotFoundError:
            # for when file does not exist (first time program is run)
            self.logger.warning(f"ey file not found: {self.key_filename}. Generating a new one.")
            private_key = self.generate_private_key()
        except (ValueError, TypeError) as e:
            # when file exists but data was not able to be loaded
            self.logger.error(f"Error loading key: {e}", exc_info=True)
            raise
        except Exception as e:
            # fopr unkown errors
            self.logger.error(f"{e}", exc_info=True)
            raise

        return private_key

    def generate_private_key(self) -> RSAPrivateKey:
        self.logger.debug("Generating new key")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        self.logger.debug(f"key generated")

        with open(self.key_filename, 'wb') as key_file:
            try:
                self.logger.debug("Saving key to file")
                key_file.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.BestAvailableEncryption(self._password.encode('utf-8'))
                    )
                )
                self.logger.info("New key is ready")

            except IOError as e:
                self.logger.error(f"IOError storing private key: {e}", exc_info=True)
                raise

            except OSError as e:
                self.logger.error(f"OSError storing private key: {e}", exc_info=True)
                raise

            except Exception as e:
                self.logger.error(f"Unexpected error storing private key: {e}", exc_info=True)
                raise

        return private_key


