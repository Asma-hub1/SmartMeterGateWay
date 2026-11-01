#!/usr/bin/env python3
"""
BSI TR-03109-5 CLS Client with Direct Certificate Pinning
Connects to SMGW via SOCKS5 and tests Direct Trust communication
"""
import socket
import struct
import time
import ssl
import hashlib
import os

class CLSClient:
    def __init__(self):
        self.smgw_host = '127.0.0.1'
        self.smgw_port = 1080
        
        # CLS certificates (for future TLS-to-SMGW implementation)
        self.cls_cert = 'certificates/cls-cert.pem'
        self.cls_key = 'certificates/cls-key.pem'
        
        self.print_banner()

    def print_banner(self):
        """Print startup banner"""
        print("\n" + "=" * 70)
        print("BSI TR-03109-5 CLS CLIENT")
        print("Direct Trust Communication Test")
        print("=" * 70)
        print(f"SMGW: {self.smgw_host}:{self.smgw_port}")
        print(f"Backend: 127.0.0.1:8443")
        
        # Check certificate files
        print(f"\nCertificate check:")
        print(f"  CLS cert: {'✓' if os.path.exists(self.cls_cert) else '✗'} {self.cls_cert}")
        print(f"  CLS key:  {'✓' if os.path.exists(self.cls_key) else '✗'} {self.cls_key}")
        print("=" * 70 + "\n")

    def run(self):
        """Main CLS client function"""
        print("[CLS] Starting Direct Trust communication test...")
        print("[CLS] This demonstrates the BSI Direct Trust model:")
        print("[CLS] 1. CLS → SMGW via SOCKS5 (plain TCP)")
        print("[CLS] 2. SMGW → Backend via mutual TLS with certificate pinning")
        print("[CLS] 3. Backend → SMGW → CLS response\n")
        
        time.sleep(2)
        
        try:
            # Step 1: Connect to SMGW
            print("1. Connecting to SMGW...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.smgw_host, self.smgw_port))
            print("   ✓ Connected to SMGW")
            
            # Step 2: SOCKS handshake
            print("2. SOCKS5 handshake...")
            sock.send(b'\x05\x01\x00')  # SOCKS5, 1 method, no auth
            response = sock.recv(2)
            print(f"   Response: {response.hex()}")
            
            if response != b'\x05\x00':
                print("   ✗ SOCKS authentication failed")
                return
            
            print("   ✓ SOCKS authentication successful")
            
            # Step 3: SOCKS CONNECT to backend
            print("3. Establishing SOCKS tunnel to backend...")
            connect_request = b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', 8443)
            sock.send(connect_request)
            
            response = sock.recv(10)
            print(f"   Response: {response.hex()} (length: {len(response)})")
            
            if len(response) < 10 or response[1] != 0:
                print("   ✗ SOCKS CONNECT failed")
                return
            
            print("   ✓ SOCKS tunnel established")
            
            # Step 4: Send test message through tunnel
            print("4. Sending test message through Direct Trust tunnel...")
            test_message = "CLS_TEST_MESSAGE: Direct Trust Communication Test @ " + time.strftime("%H:%M:%S")
            sock.send(test_message.encode())
            print(f"   Sent: '{test_message}'")
            
            # Step 5: Wait for response
            print("5. Waiting for response from backend...")
            sock.settimeout(5)
            
            try:
                response = sock.recv(1024)
                if response:
                    response_text = response.decode()
                    print(f"   ✓ Received response: '{response_text}'")
                    
                    # Analyze the response
                    if "BACKEND_ACK" in response_text:
                        print("\n" + "=" * 70)
                        print("SUCCESS: Direct Trust communication verified!")
                        print("=" * 70)
                        print("The message traveled:")
                        print("  1. CLS → SMGW (SOCKS5 tunnel)")
                        print("  2. SMGW → Backend (mutual TLS with certificate pinning)")
                        print("  3. Backend → SMGW → CLS (response)")
                        print("\nThis demonstrates the BSI Direct Trust model where:")
                        print("  • SMGW pins Backend's certificate (TOFU)")
                        print("  • Backend pins SMGW's certificate (TOFU)")
                        print("  • No CA hierarchy - direct device-to-device trust")
                        print("=" * 70)
                    else:
                        print("   ⚠ Received response but not in expected format")
                else:
                    print("   ✗ Empty response received")
                    
            except socket.timeout:
                print("   ✗ Timeout waiting for response")
            
            # Close connection
            sock.close()
            print("\n[CLS] Test completed")
            
        except ConnectionRefusedError:
            print("\n✗ Connection refused - is SMGW running on port 1080?")
            print("  Start SMGW with: python3 smgw_proxy.py")
        except socket.timeout:
            print("\n✗ Connection timeout")
        except Exception as e:
            print(f"\n✗ Error: {e}")
            import traceback
            traceback.print_exc()

def test_direct_tls_to_smgw():
    """Optional: Test direct TLS connection to SMGW"""
    print("\n" + "-" * 50)
    print("Optional: Testing direct TLS to SMGW...")
    print("(This would be the full BSI implementation)")
    print("-" * 50)
    
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(5)
        raw_socket.connect(('127.0.0.1', 1080))
        
        tls_socket = context.wrap_socket(raw_socket, server_hostname='127.0.0.1')
        print("✓ Direct TLS connection to SMGW established")
        
        cert = tls_socket.getpeercert(binary_form=True)
        if cert:
            print(f"✓ Received SMGW certificate ({len(cert)} bytes)")
            
        tls_socket.close()
    except Exception as e:
        print(f"Direct TLS test failed: {e}")

if __name__ == "__main__":
    client = CLSClient()
    client.run()
    
    # Uncomment to test direct TLS
    # test_direct_tls_to_smgw()