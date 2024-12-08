import hmac
import hashlib

# Generate HMAC for the given data and key
def generate_hmac(data, key):
    return hmac.new(key, data, hashlib.sha256).hexdigest()

# Verify the HMAC
def verify_hmac(data, key, stored_hmac):
    calculated_hmac = generate_hmac(data, key)
    return hmac.compare_digest(calculated_hmac, stored_hmac)