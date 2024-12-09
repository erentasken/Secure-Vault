import platform
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import json
import bcrypt
import base64
from key_gen import key_generator
from file_encrypt import decrypt_file_save, encrypt_file_save

CONFIG_FILE = "config.json"
ENCRYPTED_FILE_EXT = '.enc'
DECRYPTED_FILE_EXT = '_decrypted'
VAULT_PATH = './vault'
MAC_FILE_EXT = '.mac'

current_user = None
current_key = None
guestmode = False

def add_to_config_file(data, username=None):
    config_data = {}

    if os.path.exists(CONFIG_FILE):
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

    if username:
        salt = get_user_data(username, "salt")
    else: 
        salt = "default salt"
        

    stored_hashed_password = get_user_data(username, "hashed_password")
    # stored_hashed_password = base64.b64decode(user_data["hashed_password"])

    if bcrypt.checkpw(password.encode('utf-8'), base64.b64decode(stored_hashed_password)):
        current_user = username
        current_key = key_generator(password, salt)
        messagebox.showinfo("Login", "Login successful!")
        update_current_user_display()
        reload_files()
        return

    messagebox.showerror("Login", "Invalid username or password.")


def get_user_data(username, data):
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config_data = json.load(f)
        user_data = config_data.get(username)

        return user_data[data]

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
    os.makedirs(user_path, exist_ok=True)

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
            if not handle_file_decryption(file_full_path):
                messagebox.showerror("Decryption", "Decryption failed.")
        elif DECRYPTED_FILE_EXT in file_path:
            open_file(file_full_path)

def handle_file_decryption(file_full_path):
    global current_key, guestmode

    if guestmode:
        key = simpledialog.askstring("Decryption Key", "Enter decryption key:")
        if key:
            key = key_generator(key, "random_salt_value")
            if not decrypt_file_save(file_full_path, key, current_user):
                return False
            reload_files()
        else:
            messagebox.showerror("Decryption", "No key provided.")
    elif current_key:
        if not decrypt_file_save(file_full_path, current_key, current_user):
            return False
        reload_files()
    else:
        messagebox.showerror("Decryption", "Please log in to decrypt files.")

    return True
def encrypt_file_dialog():
    file_path = filedialog.askopenfilename(title="Select a file to encrypt", filetypes=[("All Files", "*.*")])
    if file_path:
        user_path = os.path.join(VAULT_PATH, current_user) if current_user else VAULT_PATH
        os.makedirs(user_path, exist_ok=True)

        if guestmode:
            key = simpledialog.askstring("Encryption Key", "Enter encryption key:")
            if key:
                key = key_generator(key, "random_salt_value")
                handle_encryption(file_path, key)
            else:
                messagebox.showerror("Encryption", "No key provided.")
        elif current_key:
            handle_encryption(file_path, current_key)
        else:
            messagebox.showerror("Encryption", "Please log in to encrypt files.")

def open_file(file_path):
    current_os = platform.system()
    try:
        if current_os == 'Darwin':
            subprocess.run(['open', file_path])
        elif current_os == 'Windows':
            os.startfile(file_path)
        elif current_os == 'Linux':
            subprocess.run(['xdg-open', file_path])
        else:
            raise OSError(f"Unsupported OS: {current_os}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open file: {e}")

def reload_files():
    show_files(VAULT_PATH, ENCRYPTED_FILE_EXT, file_listbox_encrypted)
    show_files(VAULT_PATH, DECRYPTED_FILE_EXT, file_listbox_decrypted)

def remove_files():
    user_path = os.path.join(VAULT_PATH, current_user) if current_user else VAULT_PATH
    for file in os.listdir(user_path):
        if DECRYPTED_FILE_EXT in file:
            os.remove(os.path.join(user_path, file))
    reload_files()

def handle_encryption(file_path, key):
    if encrypt_file_save(file_path, key, current_user):
        messagebox.showinfo("Encryption", "File encrypted successfully!")
        reload_files()
    else:
        messagebox.showerror("Encryption", "Encryption failed.")

def enable_guest_mode():
    global current_user, current_key, guestmode

    guestmode = True
    current_user = "guest"
    current_key = None
    os.makedirs(os.path.join(VAULT_PATH, current_user), exist_ok=True)
    update_current_user_display()
    reload_files()
    messagebox.showinfo("Guest Mode", "You are now in Guest mode.")

root = tk.Tk()
root.title("File Vault")

root.geometry("800x600")
root.configure(bg="#f0f0f0")

user_label = tk.Label(root, text="Not logged in", anchor="w", font=("Helvetica", 14), bg="#f0f0f0")
user_label.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

button_frame = tk.Frame(root, bg="#f0f0f0")
button_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

reload_button = tk.Button(button_frame, text="Reload Files", command=reload_files, width=15, bg="#4CAF50", fg="white", font=("Helvetica", 12), relief="raised")
reload_button.grid(row=0, column=0, padx=5, pady=5)

remove_button = tk.Button(button_frame, text="Remove Decrypted Files", command=remove_files, width=20, bg="#4CAF50", fg="white", font=("Helvetica", 12), relief="raised")
remove_button.grid(row=0, column=1, padx=5, pady=5)

encrypt_button = tk.Button(button_frame, text="Encrypt A File", command=encrypt_file_dialog, width=15, bg="#4CAF50", fg="white", font=("Helvetica", 12), relief="raised")
encrypt_button.grid(row=0, column=2, padx=5, pady=5)

encrypted_frame = tk.Frame(root, bg="#f0f0f0")
encrypted_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

scrollbar_encrypted = tk.Scrollbar(encrypted_frame)
file_listbox_encrypted = tk.Listbox(encrypted_frame, height=10, width=40, yscrollcommand=scrollbar_encrypted.set, font=("Helvetica", 12))
file_listbox_encrypted.grid(row=0, column=0, padx=5)
scrollbar_encrypted.grid(row=0, column=1, sticky="ns")
scrollbar_encrypted.config(command=file_listbox_encrypted.yview)

scrollbar_decrypted = tk.Scrollbar(encrypted_frame)
file_listbox_decrypted = tk.Listbox(encrypted_frame, height=10, width=40, yscrollcommand=scrollbar_decrypted.set, font=("Helvetica", 12))
file_listbox_decrypted.grid(row=0, column=2, padx=5)
scrollbar_decrypted.grid(row=0, column=3, sticky="ns")
scrollbar_decrypted.config(command=file_listbox_decrypted.yview)

file_listbox_encrypted.bind("<Double-1>", lambda event: on_file_double_click(event, file_listbox_encrypted))
file_listbox_decrypted.bind("<Double-1>", lambda event: on_file_double_click(event, file_listbox_decrypted))

button_frame_bottom = tk.Frame(root, bg="#f0f0f0")
button_frame_bottom.grid(row=3, column=0, padx=10, pady=10, sticky="w")

register_button = tk.Button(button_frame_bottom, text="Register", command=register_user, width=15, bg="#4CAF50", fg="white", font=("Helvetica", 12), relief="raised")
register_button.grid(row=0, column=0, padx=5, pady=5)

login_button = tk.Button(button_frame_bottom, text="Login", command=login_user, width=15, bg="#4CAF50", fg="white", font=("Helvetica", 12), relief="raised")
login_button.grid(row=0, column=1, padx=5, pady=5)

guest_button = tk.Button(button_frame_bottom, text="Guest Mode", command=enable_guest_mode, width=15, bg="#4CAF50", fg="white", font=("Helvetica", 12), relief="raised")
guest_button.grid(row=0, column=2, padx=5, pady=5)


# print("Test", get_user_data("eren"))

reload_files()
root.mainloop()