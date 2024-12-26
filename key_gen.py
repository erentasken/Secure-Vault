import hashlib

iterations = 100000
key_length = 32

def key_generator(password, salt):
    password_bytes = password.encode('utf-8')
    
    if isinstance(salt, str):
        salt_bytes = salt.encode('utf-8')
    else:
        salt_bytes = salt
    
    key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, iterations, dklen=key_length)
    
    return bytearray(key)