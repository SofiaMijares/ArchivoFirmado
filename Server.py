import socket
import struct
import nacl.utils
from nacl.bindings import crypto_aead_chacha20poly1305_encrypt
from nacl.signing import SigningKey
import nacl.secret

def receive_file_size(sck: socket.socket):
    fmt = "<Q"
    expected_bytes = struct.calcsize(fmt)
    received_bytes = 0
    stream = bytes()
    while received_bytes < expected_bytes:
        chunk = sck.recv(expected_bytes - received_bytes)
        stream += chunk
        received_bytes += len(chunk)
    filesize = struct.unpack(fmt, stream)[0]
    return filesize

def receive_file(sck: socket.socket, filename):
    filesize = receive_file_size(sck)
    with open(filename, "wb") as f:
        received_bytes = 0
        while received_bytes < filesize:
            chunk = sck.recv(1024)
            if chunk:
                f.write(chunk)
                received_bytes += len(chunk)
                
with socket.create_server(("localhost", 10000)) as server:
    print("Esperando al cliente...")
    conn, address = server.accept()
    print(f"{address[0]}:{address[1]} conectado.")
    print("Recibiendo archivo...")
    receive_file(conn, "PruebaCifrada.txt")
    print("Archivo recibido.")
print("Conexión cerrada.")

key = nacl.utils.random(32)
nonce = nacl.utils.random(8)

# Apertura de archivo recibido
file = open("Prueba.txt", "rb")
data = file.read()
file.close()

# Cifrado de archivo
cf = crypto_aead_chacha20poly1305_encrypt(data, None, nonce, key)
file = open("PruebaCifrada.txt", "wb")


# Generate a new random signing key
signing_key = SigningKey.generate()

# Sign a message with the signing key
signed = signing_key.sign(cf)
file.write(signed)
file.close()

# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key

# Serialize the verify key to send it to a third party
verify_key_bytes = verify_key.encode()

print("signed key:", signed)
print("verify key:", verify_key_bytes)




