import socket
import threading

CLS_LISTEN = ("127.0.0.1", 8444)
BACKEND_ADDR = ("127.0.0.1", 9443)

def forward(src, dst):
    """
    Forward encrypted bytes without inspecting or modifying them.
    SMGW has no knowledge of TLS or plaintext.
    """
    while True:
        data = src.recv(4096)
        #print(data)
        if not data:
            break
        dst.sendall(data)

# Listen for CLS connection
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(CLS_LISTEN)
listener.listen(1)

print("SMGW: waiting for CLS connection...")

cls_conn, _ = listener.accept()
print("SMGW: CLS connected")

# Connect to backend
backend_conn = socket.create_connection(BACKEND_ADDR)
print("SMGW: connected to Backend")

# Bidirectional forwarding of encrypted traffic
threading.Thread(target=forward, args=(cls_conn, backend_conn)).start()
threading.Thread(target=forward, args=(backend_conn, cls_conn)).start()
