#!/usr/bin/env python3
"""
BSI TR-03109-5 SMGW Proxy - Working with proper certificates
"""
import socket
import ssl
import threading
import struct
import os
import hashlib

class SOCKSTLSProxy:
    def __init__(self):
        self.socks_port = 1080
        self.backend_host = '127.0.0.1'
        self.backend_port = 8443
        
        # Certificate files from your script
        self.smgw_cert = 'certificates/smgw-cert.pem'
        self.smgw_key = 'certificates/smgw-key.pem'
        self.backend_cert = 'certificates/backend-cert.pem'
        
        self.print_banner()

    def print_banner(self):
        """Print startup banner"""
        print("\n" + "=" * 70)
        print("BSI TR-03109-5 SMGW PROXY")
        print("Working with BSI-compliant certificates")
        print("=" * 70)
        print(f"Listen: 127.0.0.1:{self.socks_port}")
        print(f"Backend: {self.backend_host}:{self.backend_port}")
        
        # Check certificate files
        print(f"\nCertificate check:")
        print(f"  SMGW cert: {'✓' if os.path.exists(self.smgw_cert) else '✗'} {self.smgw_cert}")
        print(f"  SMGW key:  {'✓' if os.path.exists(self.smgw_key) else '✗'} {self.smgw_key}")
        print(f"  Backend cert: {'✓' if os.path.exists(self.backend_cert) else '✗'} {self.backend_cert}")
        print("=" * 70 + "\n")

    def connect_to_backend(self):
        """Establish TLS connection to backend with client certificate"""
        try:
            print("[BACKEND] Connecting with mutual TLS...")
            
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            
            # Load SMGW client certificate
            context.load_cert_chain(
                certfile=self.smgw_cert,
                keyfile=self.smgw_key
            )
            print("[CERT] ✓ Loaded SMGW certificate")
            
            # Load backend certificate for verification
            context.load_verify_locations(cafile=self.backend_cert)
            context.verify_mode = ssl.CERT_REQUIRED
            print("[CERT] ✓ Loaded backend certificate for verification")
            
            # Create socket
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(10)
            
            # Connect to backend
            print(f"[BACKEND] Connecting to {self.backend_host}:{self.backend_port}...")
            raw_socket.connect((self.backend_host, self.backend_port))
            print("[BACKEND] ✓ TCP connection established")
            
            # Wrap with TLS
            ssl_socket = context.wrap_socket(
                raw_socket, 
                server_hostname=self.backend_host,
                do_handshake_on_connect=True
            )
            print("[TLS] ✓ Handshake completed")
            
            # Verify backend certificate
            cert_der = ssl_socket.getpeercert(binary_form=True)
            if cert_der:
                print(f"[CERT] Received backend certificate ({len(cert_der)} bytes)")
                
                # Calculate fingerprint
                cert_hash = hashlib.sha256(cert_der).hexdigest().upper()
                fingerprint = ':'.join(cert_hash[i:i+2] for i in range(0, len(cert_hash), 2))
                
                # Load expected fingerprint
                expected_fingerprint = ""
                if os.path.exists('certificates/backend-fingerprint.txt'):
                    with open('certificates/backend-fingerprint.txt', 'r') as f:
                        expected_fingerprint = f.read().strip()
                        
                if expected_fingerprint and fingerprint == expected_fingerprint:
                    print(f"[CERT] ✓ Backend certificate verified (pinned)")
                    print(f"[CERT]   Fingerprint: {fingerprint[:20]}...")
                else:
                    print(f"[CERT] ⚠ Certificate valid but fingerprint differs")
            
            print("[BACKEND] ✓ Connection established")
            return ssl_socket
            
        except ssl.SSLError as e:
            print(f"[TLS] Error: {e}")
            return None
        except ConnectionRefusedError:
            print(f"[BACKEND] ✗ Connection refused - is backend running?")
            return None
        except Exception as e:
            print(f"[BACKEND] Error: {e}")
            return None

    def handle_socks_handshake(self, client_socket):
        """Handle SOCKSv5 handshake (BSI pages 16-18)"""
        try:
            data = client_socket.recv(1024)
            if len(data) < 3:
                return False
                
            version, nmethods = struct.unpack('!BB', data[:2])
            if version != 5:
                print("[SOCKS] Not SOCKSv5")
                return False
            
            print(f"[SOCKS] Version: {version}, methods: {nmethods}")
            client_socket.send(b'\x05\x00')  # Accept no authentication
            return True
            
        except Exception as e:
            print(f"[SOCKS] Handshake error: {e}")
            return False

    def handle_socks_connect(self, client_socket):
        """Handle SOCKS CONNECT command (BSI page 17)"""
        try:
            data = client_socket.recv(1024)
            if len(data) < 10:
                print(f"[SOCKS] Short CONNECT request: {len(data)} bytes")
                return None
                
            version, cmd, rsv, atype = struct.unpack('!BBBB', data[:4])
            
            if version != 5 or cmd != 1:
                print(f"[SOCKS] Not CONNECT command")
                return None
            
            if atype == 1:  # IPv4
                addr = socket.inet_ntoa(data[4:8])
                port = struct.unpack('!H', data[8:10])[0]
                print(f"[SOCKS] CONNECT to {addr}:{port}")
                
                # Connect to backend with mutual TLS
                backend_socket = self.connect_to_backend()
                if backend_socket:
                    # Send SOCKS success response (BSI requirement)
                    response = b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
                    client_socket.send(response)
                    print("[SOCKS] ✓ Tunnel established")
                    return backend_socket
                else:
                    # Send failure response
                    client_socket.send(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                    print("[SOCKS] ✗ Backend connection failed")
                    return None
                    
            return None
            
        except Exception as e:
            print(f"[SOCKS] CONNECT error: {e}")
            return None

    def handle_client(self, client_socket, addr):
        """Handle complete client connection"""
        client_ip, client_port = addr
        print(f"\n[CLIENT] New connection from {client_ip}:{client_port}")
        
        backend_socket = None
        
        try:
            # SOCKS handshake
            if not self.handle_socks_handshake(client_socket):
                print("[SOCKS] ✗ Handshake failed")
                return
            
            print("[SOCKS] ✓ Handshake successful")
            
            # SOCKS CONNECT
            backend_socket = self.handle_socks_connect(client_socket)
            if not backend_socket:
                print("[SOCKS] ✗ CONNECT failed")
                return
            
            # Data forwarding (BSI requirement)
            print("[TUNNEL] Starting data forwarding...")
            
            # Forward data from CLS to Backend
            client_socket.settimeout(5)
            data = client_socket.recv(4096)
            if data:
                print(f"[DATA] CLS→Backend: {len(data)} bytes")
                backend_socket.send(data)
                
                # Wait for response from Backend
                backend_socket.settimeout(5)
                response = backend_socket.recv(4096)
                if response:
                    print(f"[DATA] Backend→CLS: {len(response)} bytes")
                    client_socket.send(response)
            
            print("[TUNNEL] Forwarding complete")
                            
        except socket.timeout:
            print("[TUNNEL] Timeout waiting for data")
        except Exception as e:
            print(f"[ERROR] Client handling: {e}")
        finally:
            client_socket.close()
            if backend_socket:
                backend_socket.close()
            print(f"[CLIENT] Connection closed\n")

    def run(self):
        """Start the proxy server"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('127.0.0.1', self.socks_port))
            server.listen(5)
            
            print("[PROXY] Ready and listening...")
            print("[PROXY] Waiting for CLS connections...\n")
            
            while True:
                client_socket, addr = server.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[PROXY] Shutting down...")
        except Exception as e:
            print(f"[ERROR] Proxy server: {e}")

if __name__ == "__main__":
    proxy = SOCKSTLSProxy()
    proxy.run()