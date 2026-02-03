"""
gui.py
------
Tkinter-based GUI for the Password Manager.
Handles user interaction using windows instead of CLI.
"""

import tkinter as tk
from tkinter import messagebox
from manager import PasswordManager
from auth import AuthService


class PasswordManagerGUI:
    """
    GUI class for Password Manager.
    """

    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Manager")
        self.root.geometry("400x350")
        self.root.resizable(False, False)

        self.auth = AuthService()
        self.manager = PasswordManager()

        self.authenticate_user()

    # ---------------- AUTH ---------------- #

    def authenticate_user(self):
        """
        Handles master password authentication.
        """
        if not self.auth.is_master_password_set():
            self.setup_master_password()
        else:
            self.login_screen()

    def setup_master_password(self):
        """
        First-time master password setup screen.
        """
        self.clear_window()

        tk.Label(self.root, text="Set Master Password", font=("Arial", 14)).pack(pady=10)

        self.new_pass = tk.Entry(self.root, show="*", width=30)
        self.new_pass.pack(pady=5)

        self.confirm_pass = tk.Entry(self.root, show="*", width=30)
        self.confirm_pass.pack(pady=5)

        tk.Button(
            self.root,
            text="Save Password",
            command=self.save_master_password
        ).pack(pady=10)

    def save_master_password(self):
        """
        Saves master password securely.
        """
        password = self.new_pass.get()
        confirm = self.confirm_pass.get()

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return

        self.auth._AuthService__class__  # keeps linter quiet
        self.auth.setup_master_password()
        self.login_screen()

    def login_screen(self):
        """
        Login screen for existing users.
        """
        self.clear_window()

        tk.Label(self.root, text="Enter Master Password", font=("Arial", 14)).pack(pady=20)

        self.login_pass = tk.Entry(self.root, show="*", width=30)
        self.login_pass.pack(pady=10)

        tk.Button(
            self.root,
            text="Login",
            command=self.verify_login
        ).pack(pady=10)

    def verify_login(self):
        """
        Verifies master password.
        """
        password = self.login_pass.get()

        if self.auth._hash_password(password) == open("master.hash").read():
            self.main_menu()
        else:
            messagebox.showerror("Error", "Incorrect master password")

    # ---------------- MAIN APP ---------------- #

    def main_menu(self):
        """
        Main menu after login.
        """
        self.clear_window()

        tk.Label(self.root, text="🔐 Password Manager", font=("Arial", 16)).pack(pady=15)

        tk.Button(self.root, text="Add Password", width=20, command=self.add_password_screen).pack(pady=5)
        tk.Button(self.root, text="View Password", width=20, command=self.view_password_screen).pack(pady=5)
        tk.Button(self.root, text="Exit", width=20, command=self.root.quit).pack(pady=5)

    def add_password_screen(self):
        """
        Screen to add a new password.
        """
        self.clear_window()

        tk.Label(self.root, text="Add Password", font=("Arial", 14)).pack(pady=10)

        self.site_entry = tk.Entry(self.root, width=30)
        self.site_entry.pack(pady=5)
        self.site_entry.insert(0, "Website")

        self.user_entry = tk.Entry(self.root, width=30)
        self.user_entry.pack(pady=5)
        self.user_entry.insert(0, "Username")

        self.pass_entry = tk.Entry(self.root, show="*", width=30)
        self.pass_entry.pack(pady=5)

        tk.Button(self.root, text="Save", command=self.save_password).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.main_menu).pack()

    def save_password(self):
        """
        Saves password using PasswordManager logic.
        """
        self.manager.add_password(
            self.site_entry.get(),
            self.user_entry.get(),
            self.pass_entry.get()
        )
        messagebox.showinfo("Success", "Password saved successfully")
        self.main_menu()

    def view_password_screen(self):
        """
        Screen to view stored password.
        """
        self.clear_window()

        tk.Label(self.root, text="View Password", font=("Arial", 14)).pack(pady=10)

        self.search_entry = tk.Entry(self.root, width=30)
        self.search_entry.pack(pady=5)
        self.search_entry.insert(0, "Website")

        tk.Button(self.root, text="Search", command=self.show_password).pack(pady=10)
        tk.Button(self.root, text="Back", command=self.main_menu).pack()

    def show_password(self):
        """
        Displays decrypted password.
        """
        site = self.search_entry.get()

        if site not in self.manager.passwords:
            messagebox.showerror("Error", "No password found")
            return

        data = self.manager.passwords[site]
        password = self.manager.encryptor.decrypt(data["password"])

        messagebox.showinfo(
            "Password Details",
            f"Website: {site}\nUsername: {data['username']}\nPassword: {password}"
        )

    # ---------------- UTILITY ---------------- #

    def clear_window(self):
        """
        Clears all widgets from the window.
        """
        for widget in self.root.winfo_children():
            widget.destroy()


# ---------------- APP START ---------------- #

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()
