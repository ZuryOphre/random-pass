import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Funcion para generar una clave a partir de una contraseña
def generate_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        iterations=100000,
        length=32,
        salt=salt,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

# Funcion para cifrar una contraseña dada
def encrypt_password(password, key):
    f = Fernet(key)
    password_bytes = password.encode()
    encrypted_password = f.encrypt(password_bytes)
    return encrypted_password

# Funcion para guardar una contraseña cifrada en un archivo
def save_password(password):
    key = generate_key(b'password') # Se genera una clave a partir de la contraseña 'password'
    encrypted_password = encrypt_password(password, key)
    with open('encrypted_passwords.txt', 'wb') as file:
        file.write(encrypted_password)
        print(f'La contraseña {password} ha sido guardada de forma segura en encrypted_passwords.txt')

# Funcion para generar una contraseña al azar
def generate_random_password(longitud=16):
    password = os.urandom(longitud).hex()[:longitud]
    return password

# Funcion principal que utiliza las anteriores
def main():
    password = generate_random_password()
    save_password(password)

if __name__ == '__main__':
    main()
