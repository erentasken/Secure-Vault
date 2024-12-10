import base64
import bcrypt

class Vault:
    def __init__(self, vaultname, password):
        self.vaultname = vaultname
        self.salt = bcrypt.gensalt(rounds=5)
        self.password = bcrypt.hashpw(password.encode('utf-8'), self.salt)

    def add_file(self, filename, file_hash):
        self.files.append({
            "name": filename,
            "hash": file_hash
        })

    def json(self):
        salt_b64 = base64.b64encode(self.salt).decode('utf-8')
        password_b64 = base64.b64encode(self.password).decode('utf-8')
        
        return {
            "salt": salt_b64,
            "password": password_b64,
        }