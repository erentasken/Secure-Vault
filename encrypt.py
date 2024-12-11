import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

import bcrypt

from integrity import generate_hmac, verify_hmac
from key_gen import key_generator
VAULT_PATH = "./vault"
VAULT_FILE = "vault"

MAC_SIZE = 64

NONCE_SIZE = 8

def encrypt(file_data, key):
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    
    ciphertext = cipher.encrypt(file_data)
    
    return nonce + ciphertext

def decrypt(encrypted_data, key):
    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]
    
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    
    decrypted_data = cipher.decrypt(ciphertext)
    
    return decrypted_data

# def encrypt_file(file_path, password:str, username):
#     with open(file_path, 'rb') as f:
#         file_data = f.read()

#     salt = bcrypt.gensalt(rounds=5)

#     key = key_generator(password, salt)

#     hash_value = generate_hmac(file_data, key)

#     data_with_hash = hash_value + file_data 

#     # Encrypt the data
#     encrypted_data = encrypt(data_with_hash, key)

#     file_name = os.path.basename(file_path)
#     file_name_bytes = file_name.encode()
#     metadata = salt + len(file_name_bytes).to_bytes(4, 'big') + file_name_bytes + len(encrypted_data).to_bytes(8, 'big')

#     vault_path = os.path.join(VAULT_PATH, username, 'vault.bat')
#     os.makedirs(os.path.dirname(vault_path), exist_ok=True)
#     existing_data = b""
#     if os.path.exists(vault_path):
#         with open(vault_path, 'rb') as vault_file:
#             existing_data = vault_file.read()


#     new_vault_data = b""
#     offset = 0
#     file_exists = False
#     while offset < len(existing_data):
#         offset += 29

#         file_name_len = int.from_bytes(existing_data[offset:offset + 4], 'big')
#         offset += 4
#         current_file_name = existing_data[offset:offset + file_name_len]
#         offset += file_name_len

#         encrypted_data_len = int.from_bytes(existing_data[offset:offset + 8], 'big')
#         offset += 8

#         if current_file_name == file_name:
#             new_vault_data += metadata + encrypted_data
#             file_exists = True
#         else:
#             new_vault_data += existing_data[offset - (file_name_len + 12):offset + encrypted_data_len]
        
#         offset += encrypted_data_len

#     if not file_exists:
#         new_vault_data += metadata + encrypted_data

#     with open(vault_path, 'wb') as vault_file:
#         vault_file.write(new_vault_data)

#     print(f"File '{file_name}' encrypted and added to the vault.")
#     return True

# def decrypt_file(target_file_name, password, vaultname, integrity=True):
#     vault_path = os.path.join(str(VAULT_PATH), vaultname, "vault.bat")

#     with open(vault_path, 'rb') as vault_file:
#         data = vault_file.read()

#     offset = 0
#     while offset < len(data):
#         salt = data[:29]
#         offset += 29
#         file_name_len = int.from_bytes(data[offset:offset + 4], 'big')
#         offset += 4
#         file_name = data[offset:offset + file_name_len]
#         offset += file_name_len
#         encrypted_data_len = int.from_bytes(data[offset:offset + 8], 'big')
#         offset += 8

#         encrypted_data = data[offset:offset+encrypted_data_len]

#         offset += encrypted_data_len

#         if file_name == target_file_name:
#             decrypted_data = decrypt(encrypted_data, salt)

#             key = key_generator(password, salt)

#             if integrity == True:
#                 stored_mac = decrypted_data[:MAC_SIZE]
#                 decrypted_data = decrypted_data[MAC_SIZE:]

#             if verify_hmac(decrypted_data, key, stored_mac) or integrity == False:
#                 decrypted_file_path = os.path.join(os.path.dirname(vault_path), file_name)
                
#                 splitted = decrypted_file_path.split(".")
                
#                 decrypted_file_path = "." + splitted[1] + "_decrypted" + "." + splitted[-1]
#                 with open(decrypted_file_path, 'wb') as f:
#                     f.write(decrypted_data)
#                 return True
#             else:
#                 print("File integrity is not verified: ERROR")

#                 return False

#     return False

# def read_all_file_names(vault_name : str):
#     vault_path = os.path.join(str(VAULT_PATH), str(vault_name), str("vault.bat"))

#     file_names = []

#     try:
#         with open(vault_path, 'rb') as vault_file:
#             data = vault_file.read()
#     except FileNotFoundError:
#         return False
    
#     offset = 0
#     while offset < len(data):
#         offset += 29
#         file_name_len = int.from_bytes(data[offset:offset + 4], 'big')
#         offset += 4
#         file_name = data[offset:offset + file_name_len].decode()
#         offset += file_name_len

#         # Add file name to the list
#         file_names.append(file_name)

#         # Skip over the encrypted data length and encrypted data
#         encrypted_data_len = int.from_bytes(data[offset:offset + 8], 'big')
#         offset += 8
#         offset += encrypted_data_len  # Move to the next file


#     return file_names

def encrypt_file(file_path, password: str, username):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    salt = bcrypt.gensalt(rounds=5)

    key = key_generator(password, salt)

    hash_value = generate_hmac(file_data, key)

    data_with_hash = hash_value + file_data

    # Encrypt the data
    encrypted_data = encrypt(data_with_hash, key)

    file_name = os.path.basename(file_path)
    file_name_bytes = file_name.encode()
    metadata = salt + len(file_name_bytes).to_bytes(4, 'big') + file_name_bytes + len(encrypted_data).to_bytes(8, 'big')

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
        # current_salt = existing_data[offset:offset + 29]
        offset += 29

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
            new_vault_data += existing_data[offset - (file_name_len + 12 + 29):offset + encrypted_data_len]

        offset += encrypted_data_len

    if not file_exists:
        new_vault_data += metadata + encrypted_data

    with open(vault_path, 'wb') as vault_file:
        vault_file.write(new_vault_data)

    print(f"File '{file_name}' encrypted and added to the vault.")
    return True

def decrypt_file(target_file_name, password, vaultname, integrity=True):
    vault_path = os.path.join(str(VAULT_PATH), vaultname, "vault.bat")

    with open(vault_path, 'rb') as vault_file:
        data = vault_file.read()

    offset = 0
    while offset < len(data):
        salt = data[offset:offset + 29]
        offset += 29
        
        file_name_len = int.from_bytes(data[offset:offset + 4], 'big')
        offset += 4
        file_name = data[offset:offset + file_name_len].decode()
        offset += file_name_len

        encrypted_data_len = int.from_bytes(data[offset:offset + 8], 'big')
        offset += 8

        encrypted_data = data[offset:offset + encrypted_data_len]

        offset += encrypted_data_len

        if file_name == target_file_name:
            key = key_generator(password, salt)
            decrypted_data = decrypt(encrypted_data, key)

            if integrity:
                stored_mac = decrypted_data[:MAC_SIZE]
                decrypted_data = decrypted_data[MAC_SIZE:]

                if not verify_hmac(decrypted_data, key, stored_mac):
                    print("File integrity is not verified: ERROR")
                    return False

            decrypted_file_path = os.path.join(os.path.dirname(vault_path), f"{file_name}_decrypted")
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)

            print(f"File '{file_name}' decrypted successfully.")
            return True

    print("Target file not found in the vault.")
    return False

def read_all_file_names(vault_name: str):
    vault_path = os.path.join(str(VAULT_PATH), str(vault_name), str("vault.bat"))

    file_names = []

    try:
        with open(vault_path, 'rb') as vault_file:
            data = vault_file.read()
    except FileNotFoundError:
        return False

    offset = 0
    while offset < len(data):
        offset += 29  # Skip salt
        file_name_len = int.from_bytes(data[offset:offset + 4], 'big')
        offset += 4
        file_name = data[offset:offset + file_name_len].decode()
        offset += file_name_len

        file_names.append(file_name)

        encrypted_data_len = int.from_bytes(data[offset:offset + 8], 'big')
        offset += 8
        offset += encrypted_data_len

    return file_names








def encrypt_vault(vaultname: str, password: str):
    """Create a vault directory and a vault.bat file."""
    # Create the path for the vault directory
    vault_dir_path = os.path.join(VAULT_PATH, vaultname)
    vault_file_path = os.path.join(vault_dir_path, "vault.bat")
    
    # Check if the vault directory already exists
    if os.path.exists(vault_dir_path):
        try: 
            with open(vault_file_path, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            return False

        salt = bcrypt.gensalt(rounds=5)

        key = key_generator(password, salt)

        hash_value = generate_hmac(data, key)

        data_with_hash = data + hash_value

        # Encrypt the data
        encrypted_data = encrypt(data_with_hash, key)
        
        # Rewrite the file with encrypted content
        with open(vault_file_path, 'wb') as f:
            f.write(salt + encrypted_data)
        
        return
    
    # Create the vault directory
    os.makedirs(vault_dir_path)
    
    # Create the vault.bat file
    with open(vault_file_path, 'w') as vault_file:
        vault_file.write("")

    # Generate salt
    salt = bcrypt.gensalt(rounds=5)

    key = key_generator(password, salt)

    # Calculate hash of data
    hash_value = generate_hmac("".encode(), key)

    # Append hash to data
    data_with_hash = "".encode() + hash_value


    # data_with_hash = data_with_hash.encode()

    # Encrypt the data with hash
    encrypted_data = encrypt(data_with_hash, key)

    # Save salt and encrypted data
    with open(vault_file_path, 'wb') as output_file:
        output_file.write(salt + encrypted_data)

    return key

def decrypt_vault(vaultname: str, password: str):
    """Decrypt a vault file and verify its hash."""
    vault_dir_path = os.path.join(VAULT_PATH, vaultname)
    vault_file_path = os.path.join(vault_dir_path, "vault.bat")

    if not os.path.exists(vault_file_path):
        raise FileNotFoundError(f"The encrypted vault file '{vault_file_path}' does not exist.")
    
    # Read encrypted data
    with open(vault_file_path, 'rb') as input_file:
        file_data = input_file.read()

    # Extract the salt and encrypted data
    extracted_salt = file_data[:29]  # Length of salt matches input salt length
    encrypted_data = file_data[29:]
    
    key = key_generator(password, extracted_salt)

    # Decrypt the data
    decrypted_data = decrypt(encrypted_data, key)
    
    # Split the decrypted data into content and hash
    data = decrypted_data[:-64]  # All but the last 32 bytes (hash size)
    hash_value = decrypted_data[-64:]  # Last 32 bytes (hash size)
    
    # Verify the hash
    if not verify_hmac(data, key, hash_value):
        raise ValueError("Hash verification failed. Data integrity compromised.")
    
    # Save the decrypted data back to the vault file
    with open(vault_file_path, 'wb') as output_file:
        output_file.write(data)
    
    print(f"Vault '{vaultname}' decrypted and restored to '{vault_file_path}'.")

    return True
