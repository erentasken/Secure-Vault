import os
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

CONFIG_FILE = "config.json"

# Updated salt_and_hash_password function to use bcrypt
def salt_and_hash_password(password):
    salt = bcrypt.gensalt(rounds=5) 
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)  # Hash the password with salt
    return salt, hashed_password

def encrypt_file(file_path, key, username):
    user_dir = os.path.join("user_files", username)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)

    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

    encrypted_file_path = os.path.join(user_dir, os.path.basename(file_path)+'.enc')
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(cipher.iv)  # Write IV at the start of the file
        enc_file.write(encrypted_data)
    return encrypted_file_path

def decrypt_file(file_path, key, username):
    # Retrieve the user-specific directory
    user_dir = os.path.join("user_files", username)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)

    with open(file_path, 'rb') as file:
        iv = file.read(16)  # First 16 bytes is the IV
        encrypted_data = file.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    # Saving the decrypted file in the user's directory
    decrypted_file_path = os.path.join(user_dir, os.path.basename(file_path).replace('.enc', '.dec'))
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    return decrypted_file_path
