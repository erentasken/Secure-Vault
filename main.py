import platform
import subprocess
import tkinter as tk
from tkinter import Listbox, filedialog, messagebox, simpledialog
import os
import json
import bcrypt
import base64
from Models.Vault import Vault
from key_gen import key_generator
from encrypt import decrypt_file, decrypt_vault, encrypt_file, encrypt_vault, read_all_file_names

CONFIG_FILE = "config.json"
DECRYPTED_FILE_EXT = '_decrypted'
# VAULT_PATH = './vault'
CurrentVaultName = None
VAULT_PATH = './vault'
VaultKey = None
Password = None

def add_to_config_file(data: Vault):
    config_data = {}

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config_data = json.load(f)
        except json.JSONDecodeError:
            print("Error decoding JSON. The file might be corrupted or empty. Starting fresh.")
            config_data = {}  # Initialize an empty dictionary if JSON is malformed
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            config_data = {}  # Default to an empty dictionary if any other error occurs

    vaultname = data.vaultname  # Assuming the Vault class has a vaultname attribute
    if vaultname:
        config_data[vaultname] = data.json()

    with open(CONFIG_FILE, "w") as f:
        json.dump(config_data, f, indent=4)

def create_vault_directory_and_file():
    global CurrentVaultName

    if CurrentVaultName is not None:
        user_vault_path = os.path.join(VAULT_PATH, CurrentVaultName)
    else:
        raise ValueError("CurrentVaultName is not set. Cannot create a vault directory.")

    if not os.path.exists(user_vault_path):
        os.makedirs(user_vault_path, exist_ok=True)
    
    vault_file_path = os.path.join(user_vault_path, "vault.bat")
    if not os.path.exists(vault_file_path):
        open(vault_file_path, "w").close()
        print(f"Empty vault file created at: {vault_file_path}")
    else:
        print(f"Vault file already exists at: {vault_file_path}")

def create_vault():
    global CurrentVaultName
    vaultname = simpledialog.askstring("Create", "Enter vault name:")
    if not vaultname:
        return

    # if os.path.exists(os.path.join(VAULT_PATH, CurrentVaultName)):
    #     messagebox.showerror("Create", "Vault already exists. Please open the vault.")
    #     return

    password = simpledialog.askstring("Create", "Enter a password:", show='*')
    if not password:
        return
    
    encrypt_vault(vaultname, password)

    print("vault created with name : ",  vaultname , " and password ;" , password)

    # vault = Vault(
    #     vaultname=vaultname,
    #     password=password,
    # )

    # CurrentVaultName = vaultname

    # create_vault_directory_and_file()

    # add_to_config_file(vault)
    messagebox.showinfo("Creation", "Vault Created Successfully!")

def open_vault():
    global CurrentVaultName, VaultKey, Password

    vaultname = simpledialog.askstring("Open Vault", "Enter Vault Name:")
    if not vaultname:
        messagebox.showerror("Open", "Provide Vault Name")
        return

    password = simpledialog.askstring("Open Vault", "Enter Vault Password:", show='*')
    if not password:
        messagebox.showerror("Open", "Provide Vault Password")
        return
    
    print("decrypting vault : ", vaultname, " password: " , password)

    if not decrypt_vault(vaultname, password):
        messagebox.showerror("Open", "Invalid Vault Name or password.")

    if not CurrentVaultName == None and not Password == None: 
        encrypt_vault(CurrentVaultName, Password)

    messagebox.showinfo("Open", "Vault Opened!")
    user_label.config(text="Opened Vault : " + vaultname)
    CurrentVaultName = vaultname
    Password = password

    # salt = get_vault_data("salt")
    
    # stored_hashed_password = get_vault_data("password")

    # if salt is None or stored_hashed_password is None:
    #     messagebox.showerror("Open", "Vault not found.")
    #     return
    

    # if bcrypt.checkpw(password.encode('utf-8'), base64.b64decode(stored_hashed_password)):
    #     if reload_files() == False:
    #         return
        
    #     VaultKey = key_generator(password, salt)
        
    #     messagebox.showinfo("Open", "Vault Opened!")
    #     user_label.config(text="Opened Vault : " + vaultname)
    #     CurrentVaultName = vaultname
    #     return
    

def get_vault_data(data):
    global CurrentVaultName
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config_data = json.load(f)
    else:
        return None

    vault_data = config_data.get(CurrentVaultName)

    if vault_data is None:
        print(f"Vault data for {CurrentVaultName} not found in config.")
        return None

    if data == "salt":
        return vault_data.get("salt")
    elif data == "password":
        return vault_data.get("password")

    return None

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

#########################################################################################3

def reload_files():
    global CurrentVaultName

    files = read_all_file_names(CurrentVaultName)

    if files == False:
        return False

    if read_all_file_names(CurrentVaultName) is False:
        return

    file_listbox_encrypted.delete(0, tk.END)
    for file in files:
        file_listbox_encrypted.insert(tk.END, file)

    # List the files in the vault directory
    file_listbox_decrypted.delete(0, tk.END)
    vault_path = os.path.join(VAULT_PATH, CurrentVaultName) if CurrentVaultName else VAULT_PATH
    for file in os.listdir(vault_path):
        if not file == "vault.bat":
            file_listbox_decrypted.insert(tk.END, file)
    
    show_files(file_listbox_encrypted)

def show_files(listbox):
    global CurrentVaultName
    files = read_all_file_names(CurrentVaultName)

    listbox.delete(0, tk.END)
    for file in files:
        listbox.insert(tk.END, file)

def remove_files():
    global CurrentVaultName
    vault_path = os.path.join(VAULT_PATH, CurrentVaultName) if CurrentVaultName else VAULT_PATH
    for file in os.listdir(vault_path):
        if DECRYPTED_FILE_EXT in file:
            os.remove(os.path.join(vault_path, file))
    reload_files()

def double_click_encrypted(event, listbox : Listbox):
    global CurrentVaultName

    selected_index = listbox.curselection()
    if selected_index:
        file_path = listbox.get(selected_index)
        user_path = os.path.join(VAULT_PATH, CurrentVaultName)
        file_full_path = os.path.join(user_path, file_path)

        if not handle_file_decryption(file_full_path):
            messagebox.showerror("Decryption", "Decryption failed.")

def double_click_decrypted(event, listbox : Listbox):
    selected_index = listbox.curselection()
    if selected_index:
        file_path = listbox.get(selected_index)
        file_full_path = os.path.join(VAULT_PATH, CurrentVaultName, file_path)
        open_file(file_full_path)

def handle_file_decryption(file_full_path):
    global Password, CurrentVaultName

    file_name = os.path.basename(file_full_path)

    if not decrypt_file(file_name, Password, CurrentVaultName):
        if CurrentVaultName: 
            messagebox.showerror("Decryption", "Decryption failed.")
        else:
            messagebox.showerror("Decryption", "Open Vault For Decryption.")
        return False
    reload_files()

    return True

def encrypt_file_dialog():
    global CurrentVaultName, CurrentKey
    file_path = filedialog.askopenfilename(title="Select a file to encrypt", filetypes=[("All Files", "*.*")])
    if file_path:
        user_path = os.path.join(VAULT_PATH, CurrentVaultName) if CurrentVaultName else VAULT_PATH
        os.makedirs(user_path, exist_ok=True)

        if not handle_encryption(file_path, VaultKey):
            messagebox.showerror("Encryption", "Encryption failed.")

def handle_encryption(file_path, key):
    global CurrentVaultName, Password
    if encrypt_file(file_path, Password, CurrentVaultName):
        messagebox.showinfo("Encryption", "File encrypted successfully!")
        reload_files()
        return True
    else:
        messagebox.showerror("Encryption", "Encryption failed.")
        return False

root = tk.Tk()
root.title("File Vault")

root.geometry("800x600")
root.configure(bg="#f0f0f0")

user_label = tk.Label(root, text="No Vault Opened", anchor="w", font=("Helvetica", 14), bg="#f0f0f0")
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

encrypted_label = tk.Label(encrypted_frame, text="Encrypted Files", font=("Helvetica", 14, "bold"), bg="#f0f0f0", anchor="center")
encrypted_label.grid(row=0, column=0, padx=5, pady=(5, 10), sticky="ew")

decrypted_label = tk.Label(encrypted_frame, text="Decrypted Files", font=("Helvetica", 14, "bold"), bg="#f0f0f0", anchor="center")
decrypted_label.grid(row=0, column=2, padx=5, pady=(5, 10), sticky="ew")

scrollbar_encrypted = tk.Scrollbar(encrypted_frame)
file_listbox_encrypted = tk.Listbox(encrypted_frame, height=10, width=40, yscrollcommand=scrollbar_encrypted.set, font=("Helvetica", 12))
file_listbox_encrypted.grid(row=1, column=0, padx=5)
scrollbar_encrypted.grid(row=1, column=1, sticky="ns")
scrollbar_encrypted.config(command=file_listbox_encrypted.yview)

scrollbar_decrypted = tk.Scrollbar(encrypted_frame)
file_listbox_decrypted = tk.Listbox(encrypted_frame, height=10, width=40, yscrollcommand=scrollbar_decrypted.set, font=("Helvetica", 12))
file_listbox_decrypted.grid(row=1, column=2, padx=5)
scrollbar_decrypted.grid(row=1, column=3, sticky="ns")
scrollbar_decrypted.config(command=file_listbox_decrypted.yview)

file_listbox_encrypted.bind("<Double-1>", lambda event: double_click_encrypted(event, file_listbox_encrypted))
file_listbox_decrypted.bind("<Double-1>", lambda event: double_click_decrypted(event, file_listbox_decrypted))


button_frame_bottom = tk.Frame(root, bg="#f0f0f0")
button_frame_bottom.grid(row=3, column=0, padx=10, pady=10, sticky="w")

create_button = tk.Button(button_frame_bottom, text="Create Vault", command=create_vault, width=15, bg="#4CAF50", fg="white", font=("Helvetica", 12), relief="raised")
create_button.grid(row=0, column=0, padx=5, pady=5)

login_button = tk.Button(button_frame_bottom, text="Open Vault", command=open_vault, width=15, bg="#4CAF50", fg="white", font=("Helvetica", 12), relief="raised")
login_button.grid(row=0, column=1, padx=5, pady=5)

# encrypt_vault("eren", "123123")
# decrypt_vault("eren", "123123")

root.mainloop()

encrypt_vault(CurrentVaultName, Password)


