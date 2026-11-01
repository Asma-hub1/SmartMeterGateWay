#!/usr/bin/env python3
"""
BSI Direct Trust System Manager
Runs all components in the correct order
"""
import subprocess
import time
import sys
import os
import signal

def run_system():
    print("\n" + "=" * 70)
    print("BSI Direct Trust System - Complete Test")
    print("Direct Certificate Pinning with TOFU")
    print("=" * 70)
    
    processes = []
    
    try:
        # Check certificates
        if not os.path.exists('certificates'):
            print("\n[SETUP] Generating certificates...")
            subprocess.run(['./generate_certificates.sh'], check=True)
            time.sleep(1)
        
        # Start Backend Server
        print("\n[1/3] Starting Backend Server...")
        backend = subprocess.Popen(
            [sys.executable, 'backend_server.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        processes.append(('Backend', backend))
        time.sleep(3)
        
        # Start SMGW Proxy
        print("[2/3] Starting SMGW Proxy...")
        smgw = subprocess.Popen(
            [sys.executable, 'smgw_proxy.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        processes.append(('SMGW', smgw))
        time.sleep(3)
        
        # Run CLS Client
        print("[3/3] Running CLS Client...")
        print("\n" + "=" * 70)
        
        cls = subprocess.run(
            [sys.executable, 'cls_client.py'],
            text=True,
            capture_output=False
        )
        
        print("\n" + "=" * 70)
        print("Test completed successfully!")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n\n⚠ Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        # Cleanup
        print("\n[Cleanup] Stopping processes...")
        for name, process in processes:
            try:
                print(f"  Stopping {name}...")
                process.terminate()
                process.wait(timeout=2)
            except:
                try:
                    process.kill()
                except:
                    pass
        
        print("\n" + "=" * 70)
        print("System stopped")
        print("=" * 70)

if __name__ == "__main__":
    run_system()