"""
manager.py
-----------
Contains the PasswordManager class which handles
business logic like saving and retrieving passwords.
"""

import json
import os
from encryption import EncryptionService


class PasswordManager:
    """
    Manages password storage and retrieval.
    Uses EncryptionService to keep passwords secure.
    """

    def __init__(self, storage_file="passwords.json"):
        """
        Constructor:
        - Initializes storage file
        - Creates EncryptionService object
        - Loads existing passwords
        """
        self.storage_file = storage_file
        self.encryptor = EncryptionService()
        self.passwords = self._load_passwords()

    def _load_passwords(self):
        """
        Private method:
        Loads passwords from JSON file if it exists.
        """
        if not os.path.exists(self.storage_file):
            return {}
        with open(self.storage_file, "r") as file:
            return json.load(file)

    def _save_passwords(self):
        """
        Private method:
        Saves passwords dictionary to JSON file.
        """
        with open(self.storage_file, "w") as file:
            json.dump(self.passwords, file, indent=4)

    def add_password(self, website: str, username: str, password: str):
        """
        Adds a new password:
        - Encrypts password
        - Stores it securely
        """
        encrypted_password = self.encryptor.encrypt(password)

        self.passwords[website] = {
            "username": username,
            "password": encrypted_password
        }

        self._save_passwords()
        print("✅ Password saved securely")

    def view_password(self, website: str):
        """
        Retrieves and decrypts password for a given website.
        """
        if website not in self.passwords:
            print("❌ No password found for this website")
            return

        data = self.passwords[website]
        decrypted_password = self.encryptor.decrypt(data["password"])

        print("\n🔐 Password Details")
        print(f"Website  : {website}")
        print(f"Username : {data['username']}")
        print(f"Password : {decrypted_password}\n")
