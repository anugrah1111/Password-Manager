"""
auth.py
-------
Handles master password setup and authentication.
Uses hashing for secure password verification.
"""

import os
import hashlib
import getpass


class AuthService:
    """
    Manages master password authentication.
    """

    def __init__(self, hash_file="master.hash"):
        self.hash_file = hash_file

    def _hash_password(self, password: str) -> str:
        """
        Hashes a password using SHA-256.
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def is_master_password_set(self) -> bool:
        """
        Checks if master password already exists.
        """
        return os.path.exists(self.hash_file)

    def setup_master_password(self):
        """
        Sets up master password for first-time users.
        """
        print("🔐 Set up a Master Password")

        while True:
            password = getpass.getpass("Create master password: ")
            confirm = getpass.getpass("Confirm master password: ")

            if password != confirm:
                print(" Passwords do not match. Try again.")
            elif len(password) < 6:
                print(" Password must be at least 6 characters.")
            else:
                break

        hashed = self._hash_password(password)

        with open(self.hash_file, "w") as file:
            file.write(hashed)

        print(" Master password set successfully\n")

    def authenticate(self) -> bool:
        """
        Authenticates user by verifying master password.
        """
        stored_hash = open(self.hash_file).read()

        for attempt in range(3):
            password = getpass.getpass("Enter master password: ")
            if self._hash_password(password) == stored_hash:
                print(" Authentication successful\n")
                return True
            else:
                print("Incorrect password")

        print(" Too many failed attempts")
        return False
