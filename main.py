import platform
import subprocess
import tkinter as tk
from tkinter import Listbox, filedialog, messagebox, simpledialog
import os
import json
from encrypt import decrypt_file, decrypt_vault, encrypt_file, encrypt_vault, read_all_file_names

DECRYPTED_FILE_EXT = '_decrypted'
CurrentVaultName = None
VAULT_PATH = './vault'
Password = None

def get_vault_path(vault_name):
    return os.path.join(VAULT_PATH, vault_name)

def get_vault_file_path(vault_name):
    return os.path.join(get_vault_path(vault_name), ".vault")

def secure_input(prompt, hide_input=False):
    return simpledialog.askstring(prompt, prompt, show="*" if hide_input else None)


def create_vault():
    global CurrentVaultName
    vaultname = secure_input("Create Vault Name:")
    if not vaultname:
        return

    password = secure_input("Enter Vault Password:", hide_input=True)
    if not password:
        return

    encrypt_vault(vaultname, password)
    messagebox.showinfo("Success", "Vault Created Successfully!")

def lock_vault():
    global CurrentVaultName, Password

    if not CurrentVaultName:
        messagebox.showerror("Lock", "No Vault Opened")
        return

    remove_files() # removes decrypted files

    encrypt_vault(CurrentVaultName, Password)
    messagebox.showinfo("Lock", "Vault Locked!")
    vault_label.config(text="No Vault Opened")
    CurrentVaultName = None
    Password = None

    file_listbox_encrypted.delete(0, tk.END)
    file_listbox_decrypted.delete(0, tk.END)
    

def unlock_vault():
    global CurrentVaultName, Password

    vaultname = simpledialog.askstring("Unlock Vault", "Enter Vault Name:")
    if not vaultname:
        messagebox.showerror("Unlock", "Provide Vault Name")
        return

    password = simpledialog.askstring("Open Vault", "Enter Vault Password:", show='*')
    if not password:
        messagebox.showerror("Unlock", "Provide Vault Password")
        return
    
    if not decrypt_vault(vaultname, password):
        messagebox.showerror("Unlock", "Invalid Vault Name or password.")
        return

    if not CurrentVaultName == None and not Password == None: 
        remove_files()
        encrypt_vault(CurrentVaultName, Password)

    messagebox.showinfo("Open", "Vault Opened!")
    vault_label.config(text="Opened Vault : " + vaultname)
    CurrentVaultName = vaultname
    Password = password

    reload_files()

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
    global CurrentVaultName

    if not CurrentVaultName:
        return

    file_listbox_encrypted.delete(0, tk.END)
    file_listbox_decrypted.delete(0, tk.END)

    files = read_all_file_names(CurrentVaultName)
    if files:
        for file in files:
            file_listbox_encrypted.insert(tk.END, file)

    vault_path = get_vault_path(CurrentVaultName)
    for file in os.listdir(vault_path):
        if file != ".vault":
            file_listbox_decrypted.insert(tk.END, file)

def remove_files():
    global CurrentVaultName
    vault_path = os.path.join(VAULT_PATH, CurrentVaultName) if CurrentVaultName else VAULT_PATH
    for file in os.listdir(vault_path):
        if DECRYPTED_FILE_EXT in file:
            os.remove(os.path.join(vault_path, file))
    reload_files()

def double_click_encrypted(event, listbox : Listbox):
    global CurrentVaultName, Password

    selected_index = listbox.curselection()
    if selected_index:
        file_path = listbox.get(selected_index)
        user_path = os.path.join(VAULT_PATH, CurrentVaultName)
        file_full_path = os.path.join(user_path, file_path)

        file_name = os.path.basename(file_full_path)

        if not decrypt_file(file_name, Password, CurrentVaultName):
            if CurrentVaultName: 
                messagebox.showerror("Decryption", "Decryption failed.")
            else:
                messagebox.showerror("Decryption", "Open Vault For Decryption.")
            return False
        reload_files()

        messagebox.showinfo("Decryption", "File decrypted successfully!")

        return True

def double_click_decrypted(event, listbox : Listbox):
    selected_index = listbox.curselection()
    if selected_index:
        file_path = listbox.get(selected_index)
        file_full_path = os.path.join(VAULT_PATH, CurrentVaultName, file_path)
        open_file(file_full_path)

def encrypt_file_dialog():
    global CurrentVaultName, Password

    if not CurrentVaultName:
        messagebox.showerror("Encryption", "Open a vault to encrypt files.")
        return

    file_path = filedialog.askopenfilename(title="Select a file to encrypt", filetypes=[("All Files", "*.*")])
    if file_path:
        user_path = os.path.join(VAULT_PATH, CurrentVaultName) if CurrentVaultName else VAULT_PATH
        os.makedirs(user_path, exist_ok=True)

        if encrypt_file(file_path, Password, CurrentVaultName):
            messagebox.showinfo("Encryption", "File encrypted successfully!")
            reload_files()
        else:
            messagebox.showerror("Encryption", "Encryption failed.")

root = tk.Tk()
root.title("Secure Vault")

root.geometry("800x500")
root.configure(bg="#f0f0f0")

vault_label = tk.Label(root, text="No Vault Opened", anchor="w", bg="#f0f0f0")
vault_label.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

button_frame = tk.Frame(root, bg="#f0f0f0")
button_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

encrypt_button = tk.Button(button_frame, text="Encrypt A File", command=encrypt_file_dialog, width=15, bg="green")
encrypt_button.grid(row=0, column=2, padx=5, pady=5)

encrypted_frame = tk.Frame(root, bg="#f0f0f0")
encrypted_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

encrypted_label = tk.Label(encrypted_frame, text="Encrypted Files", bg="#f0f0f0", anchor="center")
encrypted_label.grid(row=0, column=0, padx=5, pady=(5, 10), sticky="ew")

decrypted_label = tk.Label(encrypted_frame, text="Decrypted Files", bg="#f0f0f0", anchor="center")
decrypted_label.grid(row=0, column=2, padx=5, pady=(5, 10), sticky="ew")

scrollbar_encrypted = tk.Scrollbar(encrypted_frame)
file_listbox_encrypted = tk.Listbox(encrypted_frame, height=10, width=40)
file_listbox_encrypted.grid(row=1, column=0, padx=5)
scrollbar_encrypted.grid(row=1, column=1, sticky="ns")
scrollbar_encrypted.config(command=file_listbox_encrypted.yview)

scrollbar_decrypted = tk.Scrollbar(encrypted_frame)
file_listbox_decrypted = tk.Listbox(encrypted_frame, height=10, width=40)
file_listbox_decrypted.grid(row=1, column=2, padx=5)
scrollbar_decrypted.grid(row=1, column=3, sticky="ns")
scrollbar_decrypted.config(command=file_listbox_decrypted.yview)

info_label = tk.Label(
    root,
    text="ℹ️ Double-click on encrypted files to decrypt them.",
    bg="#f0f0f0",
    padx=10,
    pady=5,
)
info_label.grid(row=4, column=0, padx=10, pady=(0, 10), sticky="w")

info_label = tk.Label(
    root,
    text="ℹ️ Double-click on decrypted file to open it.",
    bg="#f0f0f0",
    padx=10,
    pady=5,
)

info_label.grid(row=5, column=0, padx=10, pady=(0, 10), sticky="w")

file_listbox_encrypted.bind("<Double-1>", lambda event: double_click_encrypted(event, file_listbox_encrypted))
file_listbox_decrypted.bind("<Double-1>", lambda event: double_click_decrypted(event, file_listbox_decrypted))


button_frame_bottom = tk.Frame(root)
button_frame_bottom.grid(row=3, column=0, padx=10, pady=10, sticky="w")

create_button = tk.Button(button_frame_bottom, text="Create Vault", command=create_vault, width=15, bg="green")
create_button.grid(row=0, column=0, padx=5, pady=5)

open_vault_button = tk.Button(button_frame_bottom, text="Unlock Vault", command=unlock_vault, width=15, bg="green")
open_vault_button.grid(row=0, column=1, padx=5, pady=5)

lock_vault_button = tk.Button(button_frame_bottom, text="Lock Vault", command=lock_vault, width=15, bg="green")
lock_vault_button.grid(row=0, column=2, padx=5, pady=5)

root.mainloop()

encrypt_vault(CurrentVaultName, Password)


