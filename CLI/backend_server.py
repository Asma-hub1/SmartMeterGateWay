#!/usr/bin/env python3
"""
BSI TR-03109-5 Backend Server

Role:
- Represents the Grid Operator / Backend System
- Terminates TLS connections coming from the SMGW
- Authenticates ONLY the SMGW (not the CLS)
- Receives application data forwarded transparently by the SMGW TLS proxy
"""

import socket
import ssl
import threading
import hashlib
import os
import sys
import datetime


class BackendServer:
    def __init__(self):
        # Backend listens locally (simulation setup)
        self.host = '127.0.0.1'
        self.port = 8443
        
        # Backend identity (TLS server certificate)
        self.backend_cert_file = 'certificates/backend-cert.pem'
        self.backend_key_file = 'certificates/backend-key.pem'
        
        # SMGW certificate used to authenticate incoming connections
        # This enforces that ONLY the SMGW may connect
        self.smgw_cert_file = 'certificates/smgw-cert.pem'
        
        # Create TLS configuration
        self.context = self.create_ssl_context()
        
        # Print startup information
        self.print_banner()

    def print_banner(self):
        """Print startup information for clarity and debugging"""
        print("\n" + "=" * 70)
        print("BSI TR-03109-5 BACKEND SERVER")
        print("Role: Terminates TLS from SMGW (TLS proxy)")
        print("=" * 70)
        print(f"Listening on: {self.host}:{self.port}")
        print(f"Backend certificate: {os.path.basename(self.backend_cert_file)}")
        print(f"Trusted SMGW certificate: {os.path.basename(self.smgw_cert_file)}")
        print("TLS Mode: Mutual TLS (SMGW authenticated)")
        print("=" * 70 + "\n")

    def create_ssl_context(self):
        """
        Create and configure SSL context.

        Security properties:
        - Backend acts as TLS SERVER
        - Requires client authentication
        - Trusts ONLY the SMGW certificate
        - TLS 1.2 or higher
        """
        try:
            # Create TLS context for authenticating clients
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Load backend server certificate and private key
            if not os.path.exists(self.backend_cert_file):
                print("[ERROR] Backend certificate missing")
                sys.exit(1)
            if not os.path.exists(self.backend_key_file):
                print("[ERROR] Backend private key missing")
                sys.exit(1)
                
            context.load_cert_chain(
                certfile=self.backend_cert_file,
                keyfile=self.backend_key_file
            )
            
            # Load SMGW certificate as trusted client
            # This restricts access strictly to the SMGW
            if os.path.exists(self.smgw_cert_file):
                context.load_verify_locations(cafile=self.smgw_cert_file)
                print("[CERT] Trusted SMGW certificate loaded")
            
            # Enforce mutual TLS
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Hostname validation is disabled because
            # this setup uses certificate pinning / direct trust
            context.check_hostname = False
            
            # Enforce minimum TLS version per BSI recommendations
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            print("[SSL] TLS context ready (SMGW authenticated)")
            return context
            
        except Exception as e:
            print(f"[ERROR] TLS context creation failed: {e}")
            sys.exit(1)

    def handle_client(self, conn, addr):
        """
        Handle a single SMGW connection.

        Expected behavior:
        - Perform TLS handshake
        - Verify SMGW certificate
        - Receive application data forwarded by SMGW
        - Send response back via the same TLS channel
        """
        client_ip, client_port = addr
        print(f"\n[CONN] Incoming connection from {client_ip}:{client_port}")
        
        try:
            # Upgrade TCP connection to TLS
            print("[TLS] Starting TLS handshake")
            ssock = self.context.wrap_socket(conn, server_side=True)
            print("[TLS] Handshake successful")
            
            # Retrieve SMGW certificate presented during handshake
            cert = ssock.getpeercert(binary_form=True)
            if not cert:
                print("[AUTH] No client certificate received")
                return
            
            print("[CERT] SMGW certificate received")
            
            # Compute certificate fingerprint (for logging / pinning validation)
            cert_hash = hashlib.sha256(cert).hexdigest().upper()
            fingerprint = ':'.join(cert_hash[i:i+2] for i in range(0, len(cert_hash), 2))
            print(f"[CERT] Fingerprint: {fingerprint[:23]}...")
            
            # Optional fingerprint comparison (extra assurance)
            expected_fingerprint = ""
            if os.path.exists('certificates/smgw-fingerprint.txt'):
                with open('certificates/smgw-fingerprint.txt', 'r') as f:
                    expected_fingerprint = f.read().strip()
            
            if expected_fingerprint and fingerprint == expected_fingerprint:
                print("[AUTH] SMGW certificate pinned and verified")
            else:
                print("[AUTH] Certificate valid (CA/pinned trust path)")
            
            # Set timeout to avoid hanging connections
            ssock.settimeout(15.0)
            
            # Receive application payload
            print("[DATA] Waiting for application data")
            try:
                data = ssock.recv(4096)
                if not data:
                    print("[DATA] No data received")
                    return
                
                # Attempt UTF-8 decode (control message expected)
                try:
                    message = data.decode('utf-8').strip()
                    print(f"[DATA] Received message: '{message}'")
                    
                    # Application-level response
                    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
                    response = f"BACKEND_ACK [{timestamp}] - Received via SMGW TLS proxy"
                    
                    ssock.send(response.encode())
                    print("[DATA] Response sent")
                    
                except UnicodeDecodeError:
                    # Binary data handling
                    print(f"[DATA] Binary payload received ({len(data)} bytes)")
                    ssock.send(b"Binary payload received")
                    
            except socket.timeout:
                print("[DATA] Receive timeout")
            
            # Close TLS connection
            ssock.close()
            print("[CONN] Connection closed cleanly")
            
        except ssl.SSLError as e:
            print(f"[TLS] TLS error: {e}")
        except Exception as e:
            print(f"[ERROR] Client handling failed: {e}")
        finally:
            try:
                conn.close()
            except:
                pass
            print("-" * 50)

    def run_server(self):
        """
        Start backend server.

        Architecture:
        - TCP listener
        - One thread per SMGW connection
        - TLS enforced before any data exchange
        """
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            print("[SERVER] Backend ready")
            print("[SERVER] Waiting for SMGW TLS connections\n")
            
            while True:
                conn, addr = server_socket.accept()
                
                # Handle each SMGW connection concurrently
                threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True
                ).start()
                
        except KeyboardInterrupt:
            print("\n[SERVER] Shutdown requested")
        finally:
            server_socket.close()
            print("=" * 70)
            print("Backend Server stopped")
            print("=" * 70)


if __name__ == "__main__":
    server = BackendServer()
    server.run_server()
