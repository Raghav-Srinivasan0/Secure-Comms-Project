from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from tkinter import filedialog as fd
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pickle
import sys
import math

keysize = 40

SIZE = 2048

FORMAT = "utf-8"

with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

HOST = input('Where to send file: ')
if HOST == "":
    HOST = '192.168.1.72'
inp = input('Port: ')
PORT = 0
if inp == "":
    PORT = 6000
else:
    PORT = int(inp)

file_to_send = r'C:\Users\woprg\Desktop\Secure Comms Project\testfile.txt'

file = open(file_to_send,'r')
file_data = list(file.read().encode('utf-8'))

file_data_arr = []
for x in range(0, int(math.ceil(float(len(file_data))/keysize))):
    temp = public_key.encrypt(
        file_data[:keysize],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(temp)
    file_data_arr.append(temp)
    del file_data[:keysize]

print(file_data_arr)

to_send = pickle.dumps(file_data_arr)

print(to_send)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
))
msg = s.recv(SIZE).decode(FORMAT)
print(f"[SERVER]: {msg}")
s.sendall(to_send)

file.close()
s.close()