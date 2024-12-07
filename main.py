import tkinter as tk
from tkinter import filedialog, messagebox
import base64
import os
import json
import bcrypt
from encrypt import decrypt_file, encrypt_file, salt_and_hash_password
from file_integrity import calculate_file_hash, verify_file_integrity
import gui
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

CONFIG_FILE = "config.json"

def add_to_config_file(data, username=None, file_path=None):
    # Save user credentials to the configuration file
    if not os.path.exists(CONFIG_FILE):
        config_data = {}
    else:
        with open(CONFIG_FILE, "r") as f:
            config_data = json.load(f)

    if username:
        config_data[username] = data
    elif file_path:
        config_data[file_path] = data

    with open(CONFIG_FILE, "w") as f:
        json.dump(config_data, f, indent=4)

def register_user(username, password):
    # Generate salt and hash the password using bcrypt
    salt = bcrypt.gensalt(rounds=5) 
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)  # Hash the password

    user_data = {
        "username": username,
        "salt": base64.b64encode(salt).decode(),  # Encoding salt in base64 to save as text
        "hashed_password": base64.b64encode(hashed_password).decode()
    }
    add_to_config_file(user_data, username=username)

    return "User registered successfully!"

def login_user(username, password):
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config_data = json.load(f)

        if username in config_data:
            user_data = config_data[username]
            salt = base64.b64decode(user_data["salt"])
            stored_hashed_password = base64.b64decode(user_data["hashed_password"])

            # Verify the password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
                print("Login successful!")
                return True, salt
            else:
                print("Invalid password.")
                return False, None
        else:
            print("Username not found.")
            return False, None
    else:
        print("No users registered yet.")
        return False, None

def file_encryption(entry_key, user_name):
    file_path = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select a file")
    if file_path:
        key = entry_key.get().encode('utf-8')
        key = key[:16].ljust(16, b'\0')  # Ensure key is 16 bytes (pad if necessary)

        if user_name == 'guest':
            encrypted_file_path = encrypt_file(file_path, key, 'guest')
        else:
            encrypted_file_path = encrypt_file(file_path, key, user_name)

        file_hash = calculate_file_hash(encrypted_file_path)

        file_data = {
            "filename": encrypted_file_path,
            "file_hash": file_hash
        }

        if file_hash:
            add_to_config_file(file_data, file_path=encrypted_file_path)
        else:
            print("Failed to calculate hash for encrypted file")

        messagebox.showinfo("Success", f"Encrypted file saved as: {encrypted_file_path}")

def file_decryption(entry_key, user_name):
    file_path = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select an encrypted file")
    if file_path:
        key = entry_key.get().encode('utf-8')
        key = key[:16].ljust(16, b'\0')  # Ensure key is 16 bytes (pad if necessary)

        print(f"Decrypting file: {file_path}")

        if not verify_file_integrity(file_path, username=user_name):
            messagebox.showerror("Integrity Error", "The file's integrity could not be verified!")
            return

        if user_name == 'guest':
            decrypted_file = decrypt_file(file_path, key, 'guest')
        else:
            decrypted_file = decrypt_file(file_path, key, user_name)

        messagebox.showinfo("Success", f"Decrypted file saved as: {decrypted_file}")

if __name__ == "__main__":
    gui.main_gui()
