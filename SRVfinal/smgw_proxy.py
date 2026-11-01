import socket, ssl

CLS_PORT = 8443
BACKEND_ADDR = ("127.0.0.1", 9443)

# --- TLS server context (for CLS) ---
server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
server_ctx.load_cert_chain("certs/smgw.pem", "certs/smgw.key")
server_ctx.load_verify_locations("certs/ca.pem")
server_ctx.verify_mode = ssl.CERT_REQUIRED

listen_sock = socket.socket()
listen_sock.bind(("127.0.0.1", CLS_PORT))
listen_sock.listen(1)

print("SMGW: waiting for CLS...")
cls_conn, _ = listen_sock.accept()
cls_tls = server_ctx.wrap_socket(cls_conn, server_side=True)

data = cls_tls.recv(4096)
print("SMGW DECRYPTED from CLS:", data.decode())

# --- TLS client context (to Backend) ---
client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
client_ctx.load_cert_chain("certs/smgw.pem", "certs/smgw.key")
client_ctx.load_verify_locations("certs/ca.pem")

backend_sock = socket.create_connection(BACKEND_ADDR)
backend_tls = client_ctx.wrap_socket(backend_sock, server_hostname="backend")

backend_tls.sendall(data)
reply = backend_tls.recv(4096)

cls_tls.sendall(reply)

cls_tls.close()
backend_tls.close()
