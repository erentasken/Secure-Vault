import base64
import tkinter as tk
from tkinter import messagebox
import bcrypt
from main import login_user, register_user, file_decryption, file_encryption

# Main application GUI
def main_gui():
    def switch_to_sessionless_mode():
        clear_window()
        # Add content at the top of the window
        tk.Label(root, text="Sessionless AES Mode", font=("Arial", 14)).pack(pady=10)

        tk.Label(root, text="Enter a 16-byte key for AES (Direct):").pack(pady=5)
        entry_key = tk.Entry(root, show="*", width=32)
        entry_key.pack(pady=5)

        encrypt_button = tk.Button(root, text="Encrypt a File", command=lambda: file_encryption(entry_key, 'guest'))
        encrypt_button.pack(pady=10)

        decrypt_button = tk.Button(root, text="Decrypt a File", command=lambda: file_decryption(entry_key, 'guest'))
        decrypt_button.pack(pady=10)

        # Frame for bottom buttons
        frame_bottom = tk.Frame(root)
        frame_bottom.pack(side="bottom", fill="x", pady=5)

        back_button = tk.Button(frame_bottom, text="Back", command=switch_to_login)
        back_button.pack(side="left", padx=10)

        # Place sessionless mode button at bottom right
        sessionless_button = tk.Button(frame_bottom, text="Sessionless Mode", command=switch_to_sessionless_mode)
        sessionless_button.pack(side="right", padx=10)

    def switch_to_session_based_mode(key=None, username=None):
        clear_window()
        # Add content at the top of the window
        tk.Label(root, text="Session-Based AES Mode", font=("Arial", 14)).pack(pady=10)

        # Show active session username
        if username:
            tk.Label(root, text=f"Active Session: {username}", font=("Arial", 12)).pack(pady=10)

        if not key:
            tk.Label(root, text="Login to proceed").pack(pady=10)
            login_button = tk.Button(root, text="Login", command=switch_to_login)
            login_button.pack(pady=10)
        else:
            tk.Label(root, text="Using Session Key").pack(pady=5)
            entry_key = tk.Entry(root, show="*", width=32)
            entry_key.insert(0, base64.b64encode(key).decode())  # Show the session-generated key
            entry_key.pack(pady=5)

            encrypt_button = tk.Button(root, text="Encrypt a File", command=lambda: file_encryption(entry_key, username))
            encrypt_button.pack(pady=10)

            decrypt_button = tk.Button(root, text="Decrypt a File", command=lambda: file_decryption(entry_key, username))
            decrypt_button.pack(pady=10)

        # Frame for bottom buttons
        frame_bottom = tk.Frame(root)
        frame_bottom.pack(side="bottom", fill="x", pady=5)

        back_button = tk.Button(frame_bottom, text="Back", command=switch_to_login)
        back_button.pack(side="left", padx=10)

    def switch_to_register():
        clear_window()
        # Add content at the top of the window
        tk.Label(root, text="Register", font=("Arial", 14)).pack(pady=10)
        tk.Label(root, text="Username:").pack(pady=5)
        entry_username = tk.Entry(root)
        entry_username.pack(pady=5)

        tk.Label(root, text="Password:").pack(pady=5)
        entry_password = tk.Entry(root, show="*")
        entry_password.pack(pady=5)

        register_button = tk.Button(root, text="Register", command=lambda: register_action(entry_username.get(), entry_password.get()))
        register_button.pack(pady=10)

        # Frame for bottom buttons
        frame_bottom = tk.Frame(root)
        frame_bottom.pack(side="bottom", fill="x", pady=5)

        back_button = tk.Button(frame_bottom, text="Back", command=switch_to_login)
        back_button.pack(side="left", padx=10)

    def register_action(username, password):
        message = register_user(username, password)
        messagebox.showinfo("Registration", message)
        switch_to_login()

    def switch_to_login():
        clear_window()
        # Add content at the top of the window
        tk.Label(root, text="Login", font=("Arial", 14)).pack(pady=10)
        tk.Label(root, text="Username:").pack(pady=5)
        entry_username = tk.Entry(root)
        entry_username.pack(pady=5)

        tk.Label(root, text="Password:").pack(pady=5)
        entry_password = tk.Entry(root, show="*")
        entry_password.pack(pady=5)

        login_button = tk.Button(root, text="Login", command=lambda: login_action(entry_username.get(), entry_password.get()))
        login_button.pack(pady=10)

        # Frame for bottom buttons
        frame_bottom = tk.Frame(root)
        frame_bottom.pack(side="bottom", fill="x", pady=5)

        register_button = tk.Button(frame_bottom, text="Register", command=switch_to_register)
        register_button.pack(side="left", padx=10)

        # Place sessionless mode button at bottom right
        sessionless_button = tk.Button(frame_bottom, text="Sessionless Mode", command=switch_to_sessionless_mode)
        sessionless_button.pack(side="right", padx=10)

    def login_action(username, password):
        success, salt = login_user(username, password)
        if success:
            # Generate session key using user credentials
            key = bcrypt.kdf(password.encode(), salt, 16, 2**8, 8)
            switch_to_session_based_mode(key, username)
        else:
            messagebox.showerror("Login Error", "Invalid username or password")

    def clear_window():
        for widget in root.winfo_children():
            widget.destroy()

    # Initial window setup
    root = tk.Tk()
    root.title("AES File Encrypt/Decrypt")
    root.geometry("350x300")

    # Switch to login screen initially
    switch_to_login()

    root.mainloop()
