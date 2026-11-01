import socket, ssl

HOST = "127.0.0.1"
PORT = 9443

ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ctx.load_cert_chain("certs/backend.pem", "certs/backend.key")
ctx.load_verify_locations("certs/ca.pem")
ctx.verify_mode = ssl.CERT_REQUIRED

sock = socket.socket()
sock.bind((HOST, PORT))
sock.listen(1)

print("Backend: waiting for SMGW...")
conn, _ = sock.accept()
tls = ctx.wrap_socket(conn, server_side=True)

data = tls.recv(4096)
print("Backend received PLAINTEXT:", data.decode())

tls.sendall(b"ACK from backend")
tls.close()
