import hashlib
import hmac

key_length = 32
iterations = 100000

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def key_generator(password, salt):
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')

    hlen = hashlib.sha256().digest_size
    num_blocks = (key_length + hlen - 1) // hlen
    key = b''

    for i in range(1, num_blocks + 1):
        block_input = salt + i.to_bytes(4, byteorder='big')

        u = hmac.new(password, block_input, hashlib.sha256).digest()
        t = u

        for _ in range(1, iterations):
            u = hmac.new(password, u, hashlib.sha256).digest()
            t = xor_bytes(t, u)
        
        key += t

    return key[:key_length]