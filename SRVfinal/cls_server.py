import socket, ssl

SMGW_ADDR = ("127.0.0.1", 8443)

ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ctx.load_cert_chain("certs/cls.pem", "certs/cls.key")
ctx.load_verify_locations("certs/ca.pem")

sock = socket.create_connection(SMGW_ADDR)
tls = ctx.wrap_socket(sock, server_hostname="smgw")

tls.sendall(b"PLAINTEXT FROM CLS")
print("CLS got:", tls.recv(4096).decode())

tls.close()
