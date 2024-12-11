import hmac
import hashlib

def generate_hmac(data, key):
    generated = hmac.new(key, data, hashlib.sha256).hexdigest().encode()
    return generated

def verify_hmac(data, key, stored_hmac):
    calculated_hmac = generate_hmac(data, key)
    return hmac.compare_digest(calculated_hmac, stored_hmac)