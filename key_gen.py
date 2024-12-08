import hashlib
import hmac

key_length = 32  # Length of the derived key (256 bits for AES-256)
iterations = 100000  # The number of iterations for PBKDF2

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def key_generator(password, salt):
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')

    # Initialize variables
    hlen = hashlib.sha256().digest_size  # SHA-256 outputs 32 bytes
    num_blocks = (key_length + hlen - 1) // hlen  # Number of blocks needed for the key
    key = b''

    # Process each block
    for i in range(1, num_blocks + 1):
        # Step 1: Create the input for the HMAC: salt + block index (as 4-byte integer)
        block_input = salt + i.to_bytes(4, byteorder='big')

        # Step 2: Perform HMAC with password and the block input
        u = hmac.new(password, block_input, hashlib.sha256).digest()
        t = u  # First block of the derived key (t_1)

        # Step 3: Perform iterations for this block
        for _ in range(1, iterations):
            u = hmac.new(password, u, hashlib.sha256).digest()
            t = xor_bytes(t, u)  # XOR each iteration with the previous result
        
        # Append this block to the final key
        key += t

    # Return the derived key, truncated to the desired key length
    return key[:key_length]