import socket
import ssl

SMGW_ADDR = ("127.0.0.1", 8444)

# TLS context: CLS authenticates backend
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain("certs/cls.pem", "certs/cls.key")
context.load_verify_locations("certs/ca.pem")

# Connect to SMGW (plain TCP)
sock = socket.create_connection(SMGW_ADDR)

# TLS is established END-TO-END with backend THROUGH SMGW
tls_sock = context.wrap_socket(sock, server_hostname="backend")
print("CLS: end-to-end TLS established with Backend")

tls_sock.sendall(b"Hello Backend, secure end-to-end TLS")

data = tls_sock.recv(4096)
print("CLS received:", data.decode())

tls_sock.close()
