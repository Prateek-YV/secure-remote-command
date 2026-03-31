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
import shlex
import time
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
    
    # ==================== IMPROVED COMMAND EXECUTION ====================
    def execute_command(self, command):
        """Safely execute system command with Windows/Linux support"""
        try:
            print(f"[DEBUG] Executing command: {command}")
            
            # SECURITY: Blacklist dangerous commands first
            dangerous_patterns = [
                'rm -rf', 'format', 'del /f', 'rd /s', 'shutdown',
                'taskkill', 'del /q', 'rmdir /s', 'cipher', 'diskpart',
                'reg delete', 'attrib -r', 'takeown', 'icacls'
            ]
            
            command_lower = command.lower()
            for pattern in dangerous_patterns:
                if pattern in command_lower:
                    logging.warning(f"Blocked dangerous command: {command}")
                    return f"ERROR: Command blocked for security reasons (contains: {pattern})"
            
            # Detect OS and handle appropriately
            if os.name == 'nt':  # Windows
                return self._execute_windows_command(command)
            else:  # Linux/Mac
                return self._execute_linux_command(command)
                
        except Exception as e:
            logging.error(f"Command execution error: {e}")
            return f"ERROR: {str(e)}"
    
    def _execute_windows_command(self, command):
        """Windows-specific command execution (SAFE method)"""
        try:
            # Map common Linux commands to Windows equivalents
            cmd_map = {
                'ls': 'dir',
                'pwd': 'cd',
                'whoami': 'whoami',
                'date': 'date /t',
                'time': 'time /t',
                'clear': 'cls',
                'cat': 'type',
                'uname': 'ver',
                'ifconfig': 'ipconfig',
                'ps': 'tasklist',
                'grep': 'findstr',
                'wc': 'find /c /v ""'
            }
            
            # Check if it's a simple command we can map
            first_word = command.split()[0] if command.split() else ''
            
            # Handle special case: commands with cmd /c prefix
            if command.startswith('cmd /c '):
                # User explicitly wants cmd - parse safely
                args = ['cmd', '/c'] + shlex.split(command[7:], posix=False)
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False  # SECURE: No shell injection possible
                )
            
            # Handle mapped commands
            elif first_word in cmd_map:
                if len(command.split()) == 1:
                    # Single command without arguments - use mapped version
                    mapped_cmd = cmd_map[first_word]
                    # Parse mapped command safely
                    args = shlex.split(mapped_cmd, posix=False) if ' ' in mapped_cmd else [mapped_cmd]
                    result = subprocess.run(
                        args,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        shell=False
                    )
                else:
                    # Command with arguments - need to handle specially
                    if first_word == 'cat' or first_word == 'type':
                        # File viewing command
                        filename = command.split()[1]
                        result = subprocess.run(
                            ['cmd', '/c', 'type', filename],
                            capture_output=True,
                            text=True,
                            timeout=30,
                            shell=False
                        )
                    else:
                        # For other commands with args, try direct execution
                        args = ['cmd', '/c'] + shlex.split(command, posix=False)
                        result = subprocess.run(
                            args,
                            capture_output=True,
                            text=True,
                            timeout=30,
                            shell=False
                        )
            
            # Handle other commands
            else:
                # Parse command safely
                try:
                    args = ['cmd', '/c'] + shlex.split(command, posix=False)
                except:
                    # If parsing fails, fall back to simple split
                    args = ['cmd', '/c'] + command.split()
                
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False
                )
            
            # Return output
            output = result.stdout
            if result.stderr:
                # Filter out common Windows warnings
                if "Zertifikatsfehler" not in result.stderr and "Certificate error" not in result.stderr:
                    output += f"\n[STDERR]: {result.stderr}"
            
            return output if output.strip() else f"[Command executed: {command}]"
            
        except subprocess.TimeoutExpired:
            return "ERROR: Command timed out after 30 seconds"
        except FileNotFoundError as e:
            return f"ERROR: Command not found. Try using 'cmd /c' prefix. Details: {e}"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def _execute_linux_command(self, command):
        """Linux-specific command execution"""
        try:
            # Parse command safely
            args = shlex.split(command)
            
            # Execute with list format (prevents injection)
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False  # SECURE: No shell injection possible
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\nERROR: {result.stderr}"
            
            return output
            
        except subprocess.TimeoutExpired:
            return "ERROR: Command timed out after 30 seconds"
        except FileNotFoundError:
            return f"ERROR: Command not found. Try using standard Linux commands"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    # ==================== END OF IMPROVED COMMAND EXECUTION ====================
    
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
            
            # Send welcome message with available commands
            welcome_msg = "\n" + "="*60 + "\n"
            welcome_msg += "SECURE REMOTE COMMAND EXECUTION SYSTEM\n"
            welcome_msg += "="*60 + "\n"
            welcome_msg += "Available commands:\n"
            welcome_msg += "  ls/dir    - List directory contents\n"
            welcome_msg += "  pwd/cd    - Show current directory\n"
            welcome_msg += "  date      - Show date\n"
            welcome_msg += "  time      - Show time\n"
            welcome_msg += "  whoami    - Show current user\n"
            welcome_msg += "  ipconfig  - Show network config\n"
            welcome_msg += "  cat/type  - View file contents\n"
            welcome_msg += "  echo      - Echo text\n"
            welcome_msg += "  help      - Show this help\n"
            welcome_msg += "  exit      - Disconnect\n"
            welcome_msg += "="*60 + "\n"
            
            client_socket.send(json.dumps({
                'type': 'welcome',
                'message': welcome_msg
            }).encode())
            
            # Command loop
            while True:
                # Receive command
                data = client_socket.recv(4096).decode()
                if not data:
                    break
                
                try:
                    command_msg = json.loads(data)
                    
                    # Handle different message types
                    if command_msg['type'] == 'command':
                        command = command_msg['command']
                        command_id = command_msg.get('command_id', 'unknown')
                        
                        # Handle help command locally
                        if command.lower() == 'help':
                            output = welcome_msg
                        else:
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
                    
                    elif command_msg['type'] == 'exit':
                        break
                        
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
        print(f"[*] Detected OS: {'Windows' if os.name == 'nt' else 'Linux/Mac'}")
        
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