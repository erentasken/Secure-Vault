import hmac
import os

from encrypt import encrypt_file, decrypt_file
from integrity import generate_hmac, verify_hmac
VAULT_PATH = "./vault"
VAULT_FILE = "vault"

MAC_SIZE = 64

def encrypt_file_save(file_path, key, username):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    if isinstance(file_data, str):
        file_data = file_data.encode()

    mac = generate_hmac(file_data, key)
    if isinstance(mac, str):
        mac = mac.encode()

    mac_and_data = mac + file_data

    encrypted_data = encrypt_file(mac_and_data, key)

    file_name = os.path.basename(file_path)
    file_name_bytes = file_name.encode()
    metadata = len(file_name_bytes).to_bytes(4, 'big') + file_name_bytes + len(encrypted_data).to_bytes(8, 'big')

    vault_path = os.path.join(VAULT_PATH, username, 'vault.bat')
    os.makedirs(os.path.dirname(vault_path), exist_ok=True)

    existing_data = b""
    if os.path.exists(vault_path):
        with open(vault_path, 'rb') as vault_file:
            existing_data = vault_file.read()

    new_vault_data = b""
    offset = 0
    file_exists = False

    while offset < len(existing_data):
        file_name_len = int.from_bytes(existing_data[offset:offset + 4], 'big')
        offset += 4
        current_file_name = existing_data[offset:offset + file_name_len].decode()
        offset += file_name_len

        encrypted_data_len = int.from_bytes(existing_data[offset:offset + 8], 'big')
        offset += 8

        if current_file_name == file_name:
            new_vault_data += metadata + encrypted_data
            file_exists = True
        else:
            new_vault_data += existing_data[offset - (file_name_len + 12):offset + encrypted_data_len]
        
        offset += encrypted_data_len

    if not file_exists:
        new_vault_data += metadata + encrypted_data

    with open(vault_path, 'wb') as vault_file:
        vault_file.write(new_vault_data)

    print(f"File '{file_name}' encrypted and added to the vault.")
    return True

def decrypt_file_save(target_file_name, key, vaultname):
    vault_path = os.path.join(str(VAULT_PATH), vaultname, "vault.bat")

    with open(vault_path, 'rb') as vault_file:
        data = vault_file.read()

    offset = 0
    while offset < len(data):
        file_name_len = int.from_bytes(data[offset:offset + 4], 'big')
        offset += 4
        file_name = data[offset:offset + file_name_len].decode()
        offset += file_name_len
        encrypted_data_len = int.from_bytes(data[offset:offset + 8], 'big')
        offset += 8

        if file_name == target_file_name:
            encrypted_data = data[offset:offset + encrypted_data_len]
            decrypted_data = decrypt_file(encrypted_data, key)

            stored_mac = decrypted_data[:MAC_SIZE]
            original_data = decrypted_data[MAC_SIZE:]

            if verify_hmac(original_data, key, stored_mac):
                print("File integrity verified: OK")

                decrypted_file_path = os.path.join(os.path.dirname(vault_path), file_name)
                
                splitted = decrypted_file_path.split(".")

                decrypted_file_path = "." + splitted[1] + "_decrypted" + "." + splitted[-1]

                with open(decrypted_file_path, 'wb') as f:
                    f.write(original_data)
                return True
            else:
                return False

        offset += encrypted_data_len
    return False


def read_all_file_names(vault_name : str):
    vault_path = os.path.join(str(VAULT_PATH), str(vault_name), str("vault.bat"))

    file_names = []

    with open(vault_path, 'rb') as vault_file:
        data = vault_file.read()

    offset = 0
    while offset < len(data):
        file_name_len = int.from_bytes(data[offset:offset + 4], 'big')
        offset += 4
        file_name = data[offset:offset + file_name_len].decode()
        offset += file_name_len

        # Add file name to the list
        file_names.append(file_name)

        # Skip over the encrypted data length and encrypted data
        encrypted_data_len = int.from_bytes(data[offset:offset + 8], 'big')
        offset += 8
        offset += encrypted_data_len  # Move to the next file

    return file_names
