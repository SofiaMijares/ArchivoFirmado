import os
import socket
import struct

def send_file(sck: socket.socket, filename):
    filesize = os.path.getsize(filename)
    sck.sendall(struct.pack("<Q", filesize))
    with open(filename, "rb") as f:
        while read_bytes := f.read(1024):
            sck.sendall(read_bytes)
            
with socket.create_connection(("localhost", 10000)) as conn:
    print("Conectado al servidor.")
    print("Enviando archivo...")
    send_file(conn, "Prueba.txt")
    print("Enviado.")
print("Conexión cerrada.")