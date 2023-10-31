#!/usr/bin/env python3

import hashlib
import base64
from Cryptodome.Cipher import AES
import sys

def decrypt_from_file():
    try:
        file = input("Enter the name of the file containing mRemoteNG password: ")
        with open(file, 'r') as f:
            encrypted_data = f.read().strip()
        return encrypted_data
    except FileNotFoundError:
        print("File not found.")
        sys.exit(1)

def decrypt_from_string():
    string = input("Enter the base64 string of the mRemoteNG password: ")
    return string

def get_password():
    password = input("Enter the custom password (Press Enter for default 'mR3m'): ")
    return password if password else "mR3m"

def decrypt_mremoteng_password():
    try:
        choice = input("Select an option:\n1. Decrypt from file\n2. Decrypt from string\nEnter your choice: ")
        if choice == '1':
            encrypted_data = decrypt_from_file()
        elif choice == '2':
            encrypted_data = decrypt_from_string()
        else:
            print("Invalid choice.")
            sys.exit(1)

        encrypted_data = base64.b64decode(encrypted_data)
        password = get_password()

        salt = encrypted_data[:16]
        associated_data = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        ciphertext = encrypted_data[32:-16]
        tag = encrypted_data[-16:]
        key = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 1000, dklen=32)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(associated_data)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print("Password: {}".format(plaintext.decode("utf-8")))

    except base64.binascii.Error:
        print("Invalid base64 string.")
        sys.exit(1)
    except (ValueError, KeyError, TypeError):
        print("Invalid encryption data or password.")
        sys.exit(1)
    except Exception as e:
        print("Decryption failed: {}".format(str(e)))
        sys.exit(1)

def main():
    decrypt_mremoteng_password()

if __name__ == "__main__":
    main()
