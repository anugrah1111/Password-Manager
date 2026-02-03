"""
encryption.py
--------------
Responsible for encrypting and decrypting passwords.
Uses Fernet symmetric encryption from the cryptography library.
"""

from cryptography.fernet import Fernet
import os


class EncryptionService:
    """
    Handles encryption and decryption logic.
    This class hides all encryption details from the rest of the app.
    """

    def __init__(self, key_file="secret.key"):
        """
        Constructor:
        - Loads an existing encryption key OR
        - Creates a new one if it does not exist
        """
        self.key_file = key_file
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)

    def _load_or_create_key(self):
        """
        Private method:
        Loads the encryption key from file.
        If the key file does not exist, it creates one.
        """
        if not os.path.exists(self.key_file):
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as file:
                file.write(key)
            return key
        else:
            with open(self.key_file, "rb") as file:
                return file.read()

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts plain text and returns encrypted string.
        """
        return self.cipher.encrypt(plain_text.encode()).decode()

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypts encrypted text and returns original plain text.
        """
        return self.cipher.decrypt(encrypted_text.encode()).decode()
