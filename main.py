"""
main.py
-------
Application entry point.
Launches the Tkinter GUI.
"""

from gui import PasswordManagerGUI
import tkinter as tk


def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
