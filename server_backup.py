import socket
import threading
import hashlib
import hmac
import logging
import json
import subprocess
import ssl
import datetime
import os
from pathlib import Path

# Configuration
HOST = '0.0.0.0'
PORT = 8888
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'
SECRET_KEY = b'super_secret_key_123'  # In production, use environment variable
LOG_FILE = 'audit.log'
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
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Generate self-signed certificate if not exists
        if not (Path(CERT_FILE).exists() and Path(KEY_FILE).exists()):
            self.generate_self_signed_cert()
        
        self.context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        
    def generate_self_signed_cert(self):
        """Generate a self-signed SSL certificate"""
        from OpenSSL import crypto
        
        # Create a key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create a self-signed certificate
        cert = crypto.X509()
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for one year
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        
        # Save certificate and key
        with open(CERT_FILE, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(KEY_FILE, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        
        print(f"[+] Generated self-signed certificate: {CERT_FILE}")
    
    def authenticate(self, client_socket):
        """Authenticate client using challenge-response"""
        try:
            # Send challenge
            challenge = os.urandom(32).hex()
            client_socket.send(json.dumps({
                'type': 'auth_challenge',
                'challenge': challenge
            }).encode())
            
            # Receive response
            response = json.loads(client_socket.recv(1024).decode())
            
            if response['type'] != 'auth_response':
                return None
            
            username = response['username']
            received_hmac = response['hmac']
            
            # Verify user exists
            if username not in USERS:
                logging.warning(f"Authentication failed: Unknown user {username}")
                return None
            
            # Compute expected HMAC
            expected = hmac.new(
                SECRET_KEY,
                f"{username}:{challenge}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Verify HMAC
            if hmac.compare_digest(received_hmac, expected):
                logging.info(f"User {username} authenticated successfully")
                return username
            else:
                logging.warning(f"Authentication failed for user {username}")
                return None
                
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            return None
    
    def execute_command(self, command):
        """Safely execute system command"""
        try:
            # Parse command into list to prevent injection
            # This is a simple parser - in production, use shlex.split()
            parts = command.strip().split()
            
            # Security: Blacklist dangerous commands
            dangerous = ['rm', 'mkfs', 'dd', 'format', 'sudo', 'su']
            if parts and parts[0] in dangerous:
                return f"ERROR: Command '{parts[0]}' is not allowed"
            
            # Execute command
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\nERROR: {result.stderr}"
            
            return output
            
        except subprocess.TimeoutExpired:
            return "ERROR: Command timed out"
        except FileNotFoundError:
            return f"ERROR: Command not found: {parts[0] if parts else 'empty'}"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        print(f"[+] New connection from {address}")
        
        try:
            # Authenticate client
            username = self.authenticate(client_socket)
            if not username:
                client_socket.send(json.dumps({
                    'status': 'error',
                    'message': 'Authentication failed'
                }).encode())
                client_socket.close()
                return
            
            # Send authentication success
            client_socket.send(json.dumps({
                'status': 'success',
                'message': 'Authenticated successfully'
            }).encode())
            
            # Command loop
            while True:
                # Receive command
                data = client_socket.recv(4096).decode()
                if not data:
                    break
                
                try:
                    command_msg = json.loads(data)
                    if command_msg['type'] != 'command':
                        continue
                    
                    command = command_msg['command']
                    command_id = command_msg.get('command_id', 'unknown')
                    
                    print(f"[{address}] Executing: {command}")
                    logging.info(f"User {username} executed: {command}")
                    
                    # Execute command
                    output = self.execute_command(command)
                    
                    # Send response
                    response = {
                        'type': 'command_result',
                        'command_id': command_id,
                        'output': output,
                        'status': 'success'
                    }
                    client_socket.send(json.dumps(response).encode())
                    
                except json.JSONDecodeError:
                    logging.error(f"Invalid JSON from {username}")
                except Exception as e:
                    logging.error(f"Error processing command: {e}")
                    
        except ssl.SSLError as e:
            logging.error(f"SSL Error: {e}")
        except Exception as e:
            logging.error(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()
            print(f"[-] Connection closed from {address}")
            logging.info(f"Connection closed from {address}")
    
    def start(self):
        """Start the server"""
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        
        print(f"[*] Secure server listening on {HOST}:{PORT}")
        print(f"[*] Using SSL/TLS encryption")
        print(f"[*] Audit log: {LOG_FILE}")
            
        # Wrap socket with SSL
        secure_server = self.context.wrap_socket(server_socket, server_side=True)
        
        try:
            while True:
                client_socket, address = secure_server.accept()
                # Handle client in new thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
        finally:
            secure_server.close()

if __name__ == "__main__":
    server = SecureCommandServer()
    server.start()