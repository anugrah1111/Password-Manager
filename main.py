"""
main.py
-------
Entry point of the Password Manager application.
Handles user interaction through command-line interface.
"""

from manager import PasswordManager
from auth import AuthService



def main():
    """
    Main function:
    - Authenticates user with master password
    - Starts password manager on success
    """
    auth = AuthService()

    # First-time setup
    if not auth.is_master_password_set():
        auth.setup_master_password()

    # Authentication check
    if not auth.authenticate():
        return  # Exit app if authentication fails
    manager = PasswordManager()

    while True:
        print("""
==========================
🔐 PASSWORD MANAGER
==========================
1. Add Password
2. View Password
3. Exit
""")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            website = input("Website: ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            manager.add_password(website, username, password)

        elif choice == "2":
            website = input("Enter website name: ").strip()
            manager.view_password(website)

        elif choice == "3":
            print("👋 Exiting Password Manager")
            break

        else:
            print("❌ Invalid choice, try again")


# Ensures main() runs only when this file is executed directly
if __name__ == "__main__":
    main()
