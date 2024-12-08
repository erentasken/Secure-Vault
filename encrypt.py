from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

NONCE_SIZE = 8

# Encrypt the file using AES CTR (AES-256)
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Generate a random nonce (also called an IV in CTR mode)
    nonce = get_random_bytes(NONCE_SIZE)  # AES block size is 16 bytes for CTR mode
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    
    # Encrypt the data (CTR mode does not require padding)
    ciphertext = cipher.encrypt(file_data)
    
    # Return the encrypted data along with the nonce (CTR mode does not use IVs like CBC)
    return nonce + ciphertext

# Decrypt the file using AES CTR (AES-256)
def decrypt_file(encrypted_data, key):
    nonce = encrypted_data[:NONCE_SIZE]  # The first 16 bytes are the nonce
    ciphertext = encrypted_data[NONCE_SIZE:]  # The rest is the ciphertext
    
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    
    # Decrypt the data (CTR mode does not require padding)
    decrypted_data = cipher.decrypt(ciphertext)
    
    return decrypted_data