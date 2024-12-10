import hmac
import hashlib

def generate_hmac(data, key):
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def verify_hmac(data, key, stored_hmac):
    calculated_hmac = generate_hmac(data, key).encode()

    print("calculated mac :", calculated_hmac)
    print("stored mac : ", stored_hmac)

    return hmac.compare_digest(calculated_hmac, stored_hmac)