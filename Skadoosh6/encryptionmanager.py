
from cryptography.hazmat.primitives import hashes  # Cryptographic hash functions
from cryptography.hazmat.primitives.asymmetric import padding  # Padding for asymmetric encryption
from cryptography.fernet import Fernet  # generates symmetric keys
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import logging
import pickle
import hashlib
from typing import Any


# Handles encryption, decryption, signing, verifying, and hashing
class EncryptionManager:
    """
    For managing encryption and decryption operations using asymmetric and symmetric keys.
    """

    logger = logging.getLogger(f"{__name__}.EncryptionManager") # Sets logger for class
    logger.setLevel(logging.ERROR)

    @staticmethod
    def generate_symmetric_key() -> bytes:
        """
        Generate a symmetric key.

        Returns:
            bytes: The generated symmetric key.
        """
        EncryptionManager.logger.debug("generating symmetric key")
        return Fernet.generate_key()

    @staticmethod
    def encrypt(data: Any, public_key: RSAPublicKey) -> bytes:
        """
        Encrypt data using hybrid encryption

        Args:
            data (str or bytes): The data to be encrypted.
            public_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey): The recipient's public key.

        Returns:
            bytes: The encrypted data.
        """
        EncryptionManager.logger.debug("encrypting data")
        try:
            if public_key is None:
                raise ValueError("Missing public key")

            # Generate a random symmetric key
            symmetric_key = EncryptionManager.generate_symmetric_key()

            # Encrypt the symmetric key with the recipients public key
            encrypted_symmetric_key = public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Use the symmetric key to encrypt the data
            cipher = Fernet(symmetric_key)
            if isinstance(data, bytes):
                cipher_text = cipher.encrypt(data)
            else:
                try:
                    cipher_text = cipher.encrypt(pickle.dumps(data))
                except pickle.PicklingError as e:
                    EncryptionManager.logger.error(f"Cannot encrypt: {data}")
                    raise ValueError

            # Combine the encrypted symmetric key and the encrypted data
            hybrid_cipher_text = encrypted_symmetric_key + cipher_text

            EncryptionManager.logger.info("Encryption successful.")
            return hybrid_cipher_text
        except Exception as e:
            # For unknown cases
            EncryptionManager.logger.error(f"Error encrypting: {e}", exc_info=True)
            return None

    @staticmethod
    def decrypt(hybrid_cipher_text: bytes, private_key: RSAPrivateKey) -> Any:
        """
        Decrypt data encrypted with this class.

        Args:
            hybrid_cipher_text (bytes): The encrypted data.
            private_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey): The recipient's private key.

        Returns:
            bytes: The decrypted data.
        """
        EncryptionManager.logger.debug("Decrypting data")
        try:
            if private_key is None:
                raise ValueError("Missing private key")

            # Extract the encrypted symmetric key and data
            encrypted_symmetric_key = hybrid_cipher_text[:256]  # Splits into key and data
            cipher_text = hybrid_cipher_text[256:]

            # Decrypt the symmetric key with the private key
            symmetric_key = private_key.decrypt(
                encrypted_symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Use the symmetric key to decrypt the data
            cipher = Fernet(symmetric_key)
            decrypted_data = cipher.decrypt(cipher_text)
            decrypted_data = pickle.loads(decrypted_data)

            EncryptionManager.logger.info("decrypted successfully.")
            return decrypted_data
        except Exception as e:
            EncryptionManager.logger.error(f"Error decrypting: {e}", exc_info=True)
            return None

    @staticmethod
    def sign(data: Any, private_key: RSAPrivateKey) -> bytes:
        """
        Sign data using an asymmetric private key.

        Args:
            data (bytes): The data to be signed.
            private_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey): The private key.

        Returns:
            bytes: The signature.
        """
        EncryptionManager.logger.debug(f"Signing: {data}")

        try:
            serialised_data = pickle.dumps(data) # convert data to bytes
        except pickle.PicklingError as e:
            EncryptionManager.logger.error(f"Can't sign: {data}")
            raise ValueError

        try:
            signature = private_key.sign(
                serialised_data,
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            EncryptionManager.logger.info(f"signed successfully: {signature}")
            return signature
        except Exception as e:
            # For unknown cases
            EncryptionManager.logger.error(f"Error signing: {e}", exc_info=True)
            return None

    @staticmethod
    def verify(signature: bytes, data: Any, public_key: RSAPublicKey) -> bool:
        """
        Verify the signature of data signed with this class

        Args:
            signature (bytes): The signature to be verified.
            data (bytes): The data.
            public_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey): The public key.

        Returns:
            bool: True if valid, False otherwise.
        """
        EncryptionManager.logger.debug(f"Verifying: {signature}")

        try:
            serialised_data = pickle.dumps(data) # converts to bytes
        except pickle.PicklingError as e:
            EncryptionManager.logger.error(f"Cannot sign: {data}")
            raise ValueError

        try:
            public_key.verify(
                signature,
                serialised_data,
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            EncryptionManager.logger.info("verification successful.")
            return True
        except Exception as e:
            # For unknown cases
            EncryptionManager.logger.error(f"Error verifying: {e}", exc_info=True)
            return False

    @staticmethod
    def hash(data):
        """
        Calculate the hash for data.

        Args:
            data (str): The data to be hashed.

        Returns:
            str: The hash.
        """
        EncryptionManager.logger.debug(f"Hashing: {data}")
        hash = hashlib.sha256(data.encode("utf-8")).hexdigest() # Hashes data
        EncryptionManager.logger.debug(f"Hashing successful: {hash}")
        return hash

    @staticmethod
    def load_public_key(public_key_bytes: bytes) -> RSAPublicKey:
        """
        Load a public key object from bytes.

        Returns:
            RSAPublicKey: The loaded public key.
        """
        try:
            # Loads the key stored as bytes into a key object
            public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

            return public_key
        except Exception as e:
            # Unknown cases
            EncryptionManager.logger.error(f"Error loading public key: {e}")
            raise ValueError
