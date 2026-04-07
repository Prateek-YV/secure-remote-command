import socket
import threading
import hashlib
import hmac
import logging
import json
import subprocess
import ssl
import os
import shlex
import time
from pathlib import Path

# Configuration
HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 8888
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'
SECRET_KEY = b'super_secret_key_123'
LOG_FILE = 'audit.log'

# User database (password is hashed)
USERS = {
    'admin': hashlib.sha256(b'admin123').hexdigest(),
    'user1': hashlib.sha256(b'user123').hexdigest()
}

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SecureCommandServer:
    def __init__(self):
        """Initialize server with SSL context"""
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.check_hostname = False
        
        # Generate certificate if not exists
        if not (Path(CERT_FILE).exists() and Path(KEY_FILE).exists()):
            self.generate_certificate()
        
        try:
            self.context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
            print("[+] SSL context loaded successfully")
        except Exception as e:
            print(f"[-] Failed to load certificate: {e}")
            print("[*] Trying to regenerate certificate...")
            self.generate_certificate()
            self.context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    
    def generate_certificate(self):
        """Generate self-signed SSL certificate"""
        try:
            from OpenSSL import crypto
            
            # Create key pair
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 2048)
            
            # Create certificate
            cert = crypto.X509()
            cert.get_subject().CN = "localhost"
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(365*24*60*60)
            cert.set_pubkey(key)
            cert.sign(key, 'sha256')
            
            # Save files
            with open(CERT_FILE, "wb") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            with open(KEY_FILE, "wb") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            
            print(f"[+] Generated certificate: {CERT_FILE}")
        except Exception as e:
            print(f"[-] Certificate generation failed: {e}")
    
    def authenticate(self, client_socket):
        """Challenge-response authentication"""
        try:
            # Generate random challenge
            challenge = os.urandom(32).hex()
            
            # Send challenge
            client_socket.send(json.dumps({
                'type': 'auth_challenge',
                'challenge': challenge
            }).encode())
            
            # Receive response
            client_socket.settimeout(10)
            data = client_socket.recv(1024).decode()
            response = json.loads(data)
            
            if response.get('type') != 'auth_response':
                return None
            
            username = response.get('username')
            received_hmac = response.get('hmac')
            
            if username not in USERS:
                logging.warning(f"Unknown user: {username}")
                return None
            
            # Compute expected HMAC
            expected = hmac.new(
                SECRET_KEY,
                f"{username}:{challenge}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Compare
            if hmac.compare_digest(received_hmac, expected):
                logging.info(f"User {username} authenticated")
                return username
            else:
                logging.warning(f"Auth failed for {username}")
                return None
                
        except Exception as e:
            logging.error(f"Auth error: {e}")
            return None
    
    def execute_command(self, command):
        """Execute command safely"""
        try:
            # Blacklist dangerous commands
            dangerous = ['rm -rf', 'format', 'mkfs', 'dd', 'shutdown', 'del /f', 'rd /s', 'taskkill']
            if any(d in command.lower() for d in dangerous):
                logging.warning(f"Blocked dangerous: {command}")
                return "ERROR: Command blocked for security reasons"
            
            # Command mapping for cross-platform
            cmd_map = {
                'ls': 'dir',
                'pwd': 'cd',
                'whoami': 'whoami',
                'date': 'date /t',
                'time': 'time /t',
                'clear': 'cls',
                'cat': 'type',
                'ifconfig': 'ipconfig'
            }
            
            first_word = command.split()[0] if command.split() else ''
            
            if os.name == 'nt':  # Windows
                if first_word in cmd_map and len(command.split()) == 1:
                    actual = cmd_map[first_word]
                    args = actual.split() if ' ' in actual else [actual]
                else:
                    try:
                        args = ['cmd', '/c'] + shlex.split(command, posix=False)
                    except:
                        args = ['cmd', '/c'] + command.split()
                
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False
                )
            else:  # Linux
                args = shlex.split(command)
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False
                )
            
            output = result.stdout
            if result.stderr:
                output += f"\n{result.stderr}"
            
            return output if output.strip() else "[Command completed]"
            
        except subprocess.TimeoutExpired:
            return "ERROR: Command timeout"
        except FileNotFoundError:
            return "ERROR: Command not found"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_client(self, client_socket, address):
        """Handle client connection"""
        print(f"[+] Connection from {address}")
        
        try:
            # Authenticate
            username = self.authenticate(client_socket)
            if not username:
                client_socket.send(json.dumps({
                    'status': 'error',
                    'message': 'Auth failed'
                }).encode())
                client_socket.close()
                return
            
            # Send success
            client_socket.send(json.dumps({
                'status': 'success',
                'message': 'Authenticated'
            }).encode())
            
            # Send welcome
            welcome = """
============================================================
SECURE REMOTE COMMAND EXECUTION SYSTEM
============================================================
Commands:
  dir/ls     - List files
  ipconfig   - Network info
  whoami     - Current user
  echo       - Echo text
  type       - View file
  mkdir      - Create directory
  del/rmdir  - Delete files/directories
  help       - Help
  exit       - Disconnect
============================================================
"""
            client_socket.send(json.dumps({
                'type': 'welcome',
                'message': welcome
            }).encode())
            
            # Command loop
            while True:
                try:
                    client_socket.settimeout(60)
                    data = client_socket.recv(4096).decode()
                    
                    if not data:
                        break
                    
                    msg = json.loads(data)
                    
                    if msg.get('type') == 'command':
                        cmd = msg.get('command', '')
                        cmd_id = msg.get('command_id', str(time.time()))
                        
                        print(f"[{address}] {username}: {cmd}")
                        logging.info(f"{username}: {cmd}")
                        
                        output = self.execute_command(cmd)
                        
                        response = {
                            'type': 'command_result',
                            'command_id': cmd_id,
                            'output': output
                        }
                        client_socket.send(json.dumps(response).encode())
                    
                    elif msg.get('type') == 'exit':
                        break
                    
                except socket.timeout:
                    print(f"[{address}] Timeout")
                    break
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"[{address}] Error: {e}")
                    break
                    
        except Exception as e:
            print(f"[{address}] Handler error: {e}")
        finally:
            client_socket.close()
            print(f"[-] Disconnected: {address}")
    
    def start(self):
        """Start the server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        
        print(f"\n{'='*50}")
        print(f"SECURE COMMAND SERVER")
        print(f"{'='*50}")
        print(f"Host: {HOST}")
        print(f"Port: {PORT}")
        print(f"Log: {LOG_FILE}")
        print(f"OS: {'Windows' if os.name == 'nt' else 'Linux'}")
        print(f"{'='*50}\n")
        
        # Wrap with SSL
        try:
            secure_server = self.context.wrap_socket(server, server_side=True)
        except Exception as e:
            print(f"[-] SSL wrap failed: {e}")
            return
        
        print("[*] Server ready. Waiting for connections...\n")
        
        try:
            while True:
                try:
                    secure_server.settimeout(1)
                    client, addr = secure_server.accept()
                    thread = threading.Thread(target=self.handle_client, args=(client, addr))
                    thread.daemon = True
                    thread.start()
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Accept error: {e}")
                    continue
                    
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
        finally:
            secure_server.close()

if __name__ == "__main__":
    server = SecureCommandServer()
    server.start()
