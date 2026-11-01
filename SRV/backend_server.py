import socket
import ssl

HOST = "127.0.0.1"
PORT = 9443

# TLS context: backend authenticates CLS
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain("certs/backend.pem", "certs/backend.key")
context.load_verify_locations("certs/ca.pem")
context.verify_mode = ssl.CERT_REQUIRED

# TCP server socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(1)

print("Backend: waiting for CLS via SMGW...")

conn, addr = sock.accept()

# TLS is established END-TO-END with CLS
tls_conn = context.wrap_socket(conn, server_side=True)
print("Backend: end-to-end TLS established")

data = tls_conn.recv(4096)
print("Backend received (plaintext):", data.decode())

tls_conn.sendall(b"ACK from Backend")

tls_conn.close()
sock.close()
