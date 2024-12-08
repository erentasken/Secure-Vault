import os

from encrypt import encrypt_file, decrypt_file
from integrity import generate_hmac, verify_hmac
VAULT_PATH = './vault/'

def encrypt_file_save(file_path, key, username):
    encrypted_data = encrypt_file(file_path, key)

    mac = generate_hmac(encrypted_data, key)

    file_name = os.path.basename(file_path)

    mac_file_path =  VAULT_PATH + "/" + username + "/" +file_name + '.mac'

    encrypted_file_path = VAULT_PATH + "/" + username + "/" + file_name + '.enc'

    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)
    with open(mac_file_path, 'w') as f:
        f.write(mac)
    return True

def decrypt_file_save(encrypted_file_path, key, username):
    mac_file_path = encrypted_file_path.replace('.enc', '.mac')

    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    with open(mac_file_path, 'r') as f:
        stored_mac = f.read().strip()

    if verify_hmac(encrypted_data, key, stored_mac):
        print("File integrity verified: OK")
    else:
        print("File integrity verification failed!")
        return False

    decrypted_data = decrypt_file(encrypted_data, key)

    encrypted_file_path = encrypted_file_path.replace('.enc', '')
    file_ext = os.path.splitext(encrypted_file_path)[1]
    file_name = os.path.splitext(encrypted_file_path)[0]
    decrypted_file_path = file_name + '_decrypted' + file_ext
    
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    return True