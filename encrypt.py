import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import hmac
import hashlib
import bcrypt
from key_gen import key_generator

VAULT_PATH = "./vault"
VAULT_FILE = "vault"

MAC_SIZE = 64
SALT_SIZE = 29
NONCE_SIZE = 8

def generate_hmac(data, key):
    generated = hmac.new(key, data, hashlib.sha256).hexdigest().encode()
    return generated

def verify_hmac(data, key, stored_hmac):
    calculated_hmac = generate_hmac(data, key)
    return hmac.compare_digest(calculated_hmac, stored_hmac)

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

def encrypt_file(file_path, password: str, username):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    salt = bcrypt.gensalt(rounds=5)

    key = key_generator(password, salt)

    hash_value = generate_hmac(file_data, key)

    data_with_hash = hash_value + file_data

    encrypted_data = encrypt(data_with_hash, key)

    file_name = os.path.basename(file_path)
    file_name_bytes = file_name.encode()
    metadata = salt + len(file_name_bytes).to_bytes(4, 'big') + file_name_bytes + len(encrypted_data).to_bytes(8, 'big')

    vault_path = os.path.join(VAULT_PATH, username, '.vault')
    os.makedirs(os.path.dirname(vault_path), exist_ok=True)
    existing_data = b""
    if os.path.exists(vault_path):
        with open(vault_path, 'rb') as vault_file:
            existing_data = vault_file.read()

    new_vault_data = b""
    offset = 0
    file_exists = False
    while offset < len(existing_data):
        offset += SALT_SIZE

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
            new_vault_data += existing_data[offset - (file_name_len + 12 + SALT_SIZE):offset + encrypted_data_len]

        offset += encrypted_data_len

    if not file_exists:
        new_vault_data += metadata + encrypted_data

    with open(vault_path, 'wb') as vault_file:
        vault_file.write(new_vault_data)

    print(f"File '{file_name}' encrypted and added to the vault.")
    return True

def decrypt_file(target_file_name, password, vaultname):
    vault_path = os.path.join(str(VAULT_PATH), vaultname, ".vault")

    with open(vault_path, 'rb') as vault_file:
        data = vault_file.read()

    offset = 0
    while offset < len(data):
        salt = data[offset:offset + SALT_SIZE]
        offset += SALT_SIZE
        
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
    vault_path = os.path.join(str(VAULT_PATH), str(vault_name), str(".vault"))

    file_names = []

    try:
        with open(vault_path, 'rb') as vault_file:
            data = vault_file.read()
    except FileNotFoundError:
        return False

    offset = 0
    while offset < len(data):
        offset += SALT_SIZE  # Skip salt
        file_name_len = int.from_bytes(data[offset:offset + 4], 'big')
        offset += 4

        try: 
            file_name = data[offset:offset + file_name_len].decode()
        except UnicodeDecodeError: 
            return False

        offset += file_name_len

        file_names.append(file_name)

        encrypted_data_len = int.from_bytes(data[offset:offset + 8], 'big')
        offset += 8
        offset += encrypted_data_len

    return file_names

def encrypt_vault(vaultname: str, password: str):
    vault_dir_path = os.path.join(VAULT_PATH, vaultname)
    vault_file_path = os.path.join(vault_dir_path, ".vault")
    
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

        encrypted_data = encrypt(data_with_hash, key)
        
        with open(vault_file_path, 'wb') as f:
            f.write(salt + encrypted_data)
        
        return
    
    os.makedirs(vault_dir_path)
    
    with open(vault_file_path, 'w') as vault_file:
        vault_file.write("")

    salt = bcrypt.gensalt(rounds=5)

    key = key_generator(password, salt)

    hash_value = generate_hmac("".encode(), key)

    data_with_hash = "".encode() + hash_value

    encrypted_data = encrypt(data_with_hash, key)

    with open(vault_file_path, 'wb') as output_file:
        output_file.write(salt + encrypted_data)

    return key

def decrypt_vault(vaultname: str, password: str):
    vault_dir_path = os.path.join(VAULT_PATH, vaultname)
    vault_file_path = os.path.join(vault_dir_path, ".vault")

    if not os.path.exists(vault_file_path):
        return False
    
    with open(vault_file_path, 'rb') as input_file:
        file_data = input_file.read()

    extracted_salt = file_data[:SALT_SIZE] 
    encrypted_data = file_data[SALT_SIZE:]
    
    key = key_generator(password, extracted_salt)

    decrypted_data = decrypt(encrypted_data, key)
    
    data = decrypted_data[:-MAC_SIZE] 
    hash_value = decrypted_data[-MAC_SIZE:]
    
    if not verify_hmac(data, key, hash_value):
        return False
    
    with open(vault_file_path, 'wb') as output_file:
        output_file.write(data)
    
    print(f"Vault '{vaultname}' decrypted and restored to '{vault_file_path}'.")

    return True