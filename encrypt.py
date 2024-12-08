from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

NONCE_SIZE = 8

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    
    ciphertext = cipher.encrypt(file_data)
    
    return nonce + ciphertext

def decrypt_file(encrypted_data, key):
    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]
    
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    
    decrypted_data = cipher.decrypt(ciphertext)
    
    return decrypted_data