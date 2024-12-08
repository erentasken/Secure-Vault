import platform
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import json
import bcrypt
import base64
from key_gen import key_generator
from main import decrypt_file_save, encrypt_file_save

CONFIG_FILE = "config.json"
ENCRYPTED_FILE_EXT = '.enc'
DECRYPTED_FILE_EXT = '_decrypted'
VAULT_PATH = './vault'

current_user = None
current_key = None
guestmode = False

def add_to_config_file(data, username=None):
    # Save user credentials to the configuration file
    if not os.path.exists(CONFIG_FILE):
        config_data = {}
    else:
        with open(CONFIG_FILE, "r") as f:
            config_data = json.load(f)

    if username:
        config_data[username] = data

    with open(CONFIG_FILE, "w") as f:
        json.dump(config_data, f, indent=4)

def register_user():
    username = simpledialog.askstring("Register", "Enter a username:")
    if not username:
        return

    password = simpledialog.askstring("Register", "Enter a password:", show='*')
    if not password:
        return

    salt = bcrypt.gensalt(rounds=5)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    user_data = {
        "username": username,
        "salt": base64.b64encode(salt).decode(),
        "hashed_password": base64.b64encode(hashed_password).decode()
    }
    add_to_config_file(user_data, username=username)
    messagebox.showinfo("Registration", "User registered successfully!")

def login_user():
    global current_user, current_key, guestmode

    guestmode = False
    username = simpledialog.askstring("Login", "Enter your username:")
    if not username:
        return

    password = simpledialog.askstring("Login", "Enter your password:", show='*')
    if not password:
        return

    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config_data = json.load(f)

        if username in config_data:
            user_data = config_data[username]
            salt = base64.b64decode(user_data["salt"])
            stored_hashed_password = base64.b64decode(user_data["hashed_password"])

            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
                current_user = username
                current_key = key_generator(password, "random_salt_value")
                messagebox.showinfo("Login", "Login successful!")
                update_current_user_display()
                reload_files()
                return

    messagebox.showerror("Login", "Invalid username or password.")

def update_current_user_display():
    if guestmode:
        user_label.config(text="Guest Mode")
    elif current_user == "guest":
        user_label.config(text="Logged in as: Guest")
    elif current_user:
        user_label.config(text=f"Logged in as: {current_user}")
    else:
        user_label.config(text="Not logged in")


def show_files(path, ext, listbox):
    user_path = os.path.join(path, current_user) if current_user else path
    if not os.path.exists(user_path):
        os.makedirs(user_path)
        

    files = [f for f in os.listdir(user_path) if ext in f]
    listbox.delete(0, tk.END)
    for file in files:
        listbox.insert(tk.END, file)

def on_file_double_click(event, listbox):
    global current_key, guestmode

    selected_index = listbox.curselection()
    if selected_index:
        file_path = listbox.get(selected_index)
        user_path = os.path.join(VAULT_PATH, current_user) if current_user else VAULT_PATH
        file_full_path = os.path.join(user_path, file_path)

        if ENCRYPTED_FILE_EXT in file_path:
            if guestmode:
                key = simpledialog.askstring("Decryption Key", "Enter decryption key:")
                if key:
                    key = key_generator(key, "random_salt_value")
                    decrypt_file_save(file_full_path, key, current_user)
                    reload_files()
                else:
                    messagebox.showerror("Decryption", "No key provided.")
            elif current_key:
                decrypt_file_save(file_full_path, current_key, current_user)
                reload_files()
            elif current_user == "guest":
                key = simpledialog.askstring("Decryption Key", "Enter decryption key:")
                if key:
                    key = key_generator(key, "random_salt_value")
                    decrypt_file_save(file_full_path, key, current_user)
                    reload_files()
                else:
                    messagebox.showerror("Decryption", "No key provided.")
            else:
                messagebox.showerror("Decryption", "Please log in to decrypt files.")
        elif DECRYPTED_FILE_EXT in file_path:
            open_file(file_full_path)

def encrypt_file_dialog():
    global current_key, guestmode

    file_path = filedialog.askopenfilename(title="Select a file to encrypt", filetypes=[("All Files", "*.*")])
    if file_path:
        user_path = os.path.join(VAULT_PATH, current_user) if current_user else VAULT_PATH
        if not os.path.exists(user_path):
            os.makedirs(user_path)

        if guestmode:
            key = simpledialog.askstring("Encryption Key", "Enter encryption key:")
            if key:
                key = key_generator(key, "random_salt_value")
                if encrypt_file_save(file_path, key, current_user):
                    messagebox.showinfo("Encryption", "File encrypted successfully!")
                    reload_files()
                else:
                    messagebox.showerror("Encryption", "Encryption failed.")
            else:
                messagebox.showerror("Encryption", "No key provided.")
        elif current_key:
            if encrypt_file_save(file_path, current_key, current_user):
                messagebox.showinfo("Encryption", "File encrypted successfully!")
                reload_files()
            else:
                messagebox.showerror("Encryption", "Encryption failed.")
        else:
            messagebox.showerror("Encryption", "Please log in to encrypt files.")

def open_file(file_path):
    current_os = platform.system()
    if current_os == 'Darwin':
        subprocess.run(['open', file_path])
    elif current_os == 'Windows':
        os.startfile(file_path)
    elif current_os == 'Linux':
        subprocess.run(['xdg-open', file_path])
    else:
        print(f"Unsupported OS: {current_os}")

def reload_files():
    show_files(VAULT_PATH, ENCRYPTED_FILE_EXT, file_listbox_encrypted)
    show_files(VAULT_PATH, DECRYPTED_FILE_EXT, file_listbox_decrypted)


def enable_guest_mode():
    global current_user, current_key, guestmode
    guestmode = True  # Disable sessionless mode if active
    current_user = "guest"   # Assign guest as the current user
    current_key = None       # Ensure no key is set
    if not os.path.exists(os.path.join(VAULT_PATH, current_user)):
        os.makedirs(os.path.join(VAULT_PATH, current_user))  # Create a folder for guest if it doesn't exist
    update_current_user_display()  # Update the UI display
    reload_files()  # Reload files for the guest user
    messagebox.showinfo("Guest Mode", "You are now in Guest mode.")


root = tk.Tk()
root.title("File Vault")

user_label = tk.Label(root, text="Not logged in", anchor="w")
user_label.pack(fill="x")

button_frame = tk.Frame(root)
button_frame.pack(pady=10)

register_button = tk.Button(button_frame, text="Register", command=register_user)
register_button.pack(side=tk.LEFT, padx=5)

login_button = tk.Button(button_frame, text="Login", command=login_user)
login_button.pack(side=tk.LEFT, padx=5)

guest_button = tk.Button(button_frame, text="Guest Mode", command=enable_guest_mode)
guest_button.pack(side=tk.LEFT, padx=5)

reload_button = tk.Button(button_frame, text="Reload Files", command=reload_files)
reload_button.pack(side=tk.LEFT, padx=5)

encrypt_button = tk.Button(button_frame, text="Encrypt A File", command=encrypt_file_dialog)
encrypt_button.pack(side=tk.LEFT, padx=5)

encrypted_frame = tk.Frame(root)
encrypted_frame.pack(pady=10)

file_listbox_encrypted = tk.Listbox(encrypted_frame, height=10, width=40)
file_listbox_encrypted.pack(side=tk.LEFT)

file_listbox_decrypted = tk.Listbox(encrypted_frame, height=10, width=40)
file_listbox_decrypted.pack(side=tk.LEFT, padx=10)

file_listbox_encrypted.bind("<Double-1>", lambda event: on_file_double_click(event, file_listbox_encrypted))
file_listbox_decrypted.bind("<Double-1>", lambda event: on_file_double_click(event, file_listbox_decrypted))

reload_files()
root.mainloop()