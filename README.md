# Secure File Vault

## Overview
The Secure File Vault is a Python application designed to encrypt and manage files within a secure vault. It allows users to create, unlock, lock, encrypt, and decrypt files, providing a user-friendly interface built with `tkinter`. This ensures file security with password-protected vaults and seamless file operations.

## Features
- **Create Vault:** Create a new vault with password protection.
- **Lock Vault:** Secure all decrypted files in the vault by re-encrypting them.
- **Unlock Vault:** Decrypt and access the contents of a vault using the correct password.
- **File Encryption:** Encrypt individual files and add them to the vault.
- **File Decryption:** Decrypt specific files and view them in their original form.
- **File Viewing:** Open decrypted files directly from the application.

## Prerequisites
- Python 3.x
- Required Python packages:
  - `tkinter`
  - `platform`
  - `subprocess`
  - `os`
  - `json`
  - Custom encryption functions: `encrypt_file`, `decrypt_file`, `encrypt_vault`, `decrypt_vault`, `read_all_file_names` (imported from `encrypt.py`)

## Installation
1. Clone the repository or download the source code.
   ```bash
   git clone https://github.com/your-repository/secure-file-vault.git
   cd secure-file-vault
   ```

2. Ensure all required dependencies are installed.

3. Place the `encrypt.py` file containing the encryption and decryption functions in the same directory as the main script.

4. Run the application.
   ```bash
   python secure_vault.py
   ```

## How to Use

### Creating a Vault
1. Click the **Create Vault** button.
2. Enter a name for the vault and a password when prompted.
3. Your new vault will be created and ready for use.

### Unlocking a Vault
1. Click the **Unlock Vault** button.
2. Enter the vault name and password.
3. The vault contents will be decrypted and displayed in the UI.

### Locking a Vault
1. Click the **Lock Vault** button.
2. All decrypted files will be removed, and the vault will be secured.

### Encrypting a File
1. Click the **Encrypt A File** button.
2. Select the file you wish to encrypt.
3. The file will be encrypted and added to the vault.

### Decrypting a File
1. Double-click on a file in the **Encrypted Files** list.
2. The file will be decrypted and displayed in the **Decrypted Files** list.

### Viewing a File
1. Double-click on a file in the **Decrypted Files** list.
2. The file will open in the default application for its type.

## File Structure
- **secure_vault.py:** Main application script.
- **encrypt.py:** Contains encryption and decryption logic.
- **vault/**: Directory where encrypted vaults and files are stored.

## Security Notes
- Ensure strong passwords for your vaults.
- Always lock the vault after use to secure the decrypted files.
- Vaults and their contents are stored in the `vault/` directory.
