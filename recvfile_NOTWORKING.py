from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pickle

def decrypt(data):
    res = []
    for encrypted in data:
        original_message = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        res.append(original_message.decode('utf-8'))
    return res

PORT = 6000

IP = socket.gethostbyname(socket.gethostname())

ADDR = (IP, PORT)

SIZE = 2048

FORMAT = "utf-8"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind(ADDR)

server.listen()

print("[LISTENING] Server is listening.")

data = []

private_key = None

while True:
    """ Server has accepted the connection from the client. """
    conn, addr = server.accept()
    print(f"[NEW CONNECTION] {addr} connected.")
    pk_data = conn.recv(4096+200)
    conn.send("Key received.".encode(FORMAT))
    print(pk_data)
    private_key = serialization.load_pem_private_key(
        pk_data,
        password=None,
        backend=default_backend()
    )
    while True:
        recv_data = conn.recv(SIZE)
        if not recv_data:
            break
        #data.append(pickle.loads(recv_data))
        data.append(recv_data)
    data = decrypt(data)
    with open('result.txt','w+') as f:
        f.writelines(data)
    #print(data)