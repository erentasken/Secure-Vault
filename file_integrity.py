import os
import hashlib
import json

CONFIG_FILE = "config.json"

def calculate_file_hash(file_path, hash_algorithm='sha256'):
    hash_function = hashlib.new(hash_algorithm)  # Choose the hash function (e.g., sha256, md5)
    try:
        with open(file_path, 'rb') as file:
            # Read the file in chunks to avoid memory issues with large files
            while chunk := file.read(8192):
                hash_function.update(chunk)
        return hash_function.hexdigest()  # Return the hexadecimal representation of the hash
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def verify_file_integrity(file_path, username,config_file=CONFIG_FILE):
    # Check if the config file exists
    if not os.path.exists(config_file):
        print(f"Config file {config_file} does not exist.")
        return False

    # Normalize the file path (to remove absolute path differences)
    normalized_file_path = os.path.basename(file_path)  # Use the filename only

    # Load the config data
    with open(config_file, 'r') as f:
        config_data = json.load(f)

    # Check if the encrypted file is in the config
    user_specific_file_path = os.path.join("user_files", username, normalized_file_path)  # Modify as needed

    if user_specific_file_path not in config_data:
        print(f"No stored hash found for {user_specific_file_path}")
        return False

    # Retrieve the stored hash from the config file
    stored_hash = config_data[user_specific_file_path]["file_hash"]
    current_hash = calculate_file_hash(file_path)

    if current_hash is None:
        print(f"Error calculating hash for {file_path}")
        return False

    # Compare the hashes
    if current_hash == stored_hash:
        print(f"File integrity check passed for {file_path}")
        return True
    else:
        print(f"File integrity check failed for {file_path}")
        return False
