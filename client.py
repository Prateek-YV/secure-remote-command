import socket
import ssl
import json
import hmac
import hashlib
import time
import threading
from datetime import datetime

# Configuration
SERVER_HOST = 'localhost'
SERVER_PORT = 8888
SECRET_KEY = b'super_secret_key_123'  # Must match server

class SecureCommandClient:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE  # For self-signed cert
        
    def connect(self):
        """Connect to server"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Wrap with SSL
            self.client_socket = self.context.wrap_socket(sock, server_hostname=SERVER_HOST)
            self.client_socket.connect((SERVER_HOST, SERVER_PORT))
            
            print(f"[+] Connected to {SERVER_HOST}:{SERVER_PORT}")
            return True
            
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def authenticate(self):
        """Authenticate with server"""
        try:
            # Receive challenge
            data = self.client_socket.recv(1024).decode()
            challenge_msg = json.loads(data)
            
            if challenge_msg['type'] != 'auth_challenge':
                print("[-] Invalid authentication protocol")
                return False
            
            challenge = challenge_msg['challenge']
            
            # Compute HMAC response
            hmac_response = hmac.new(
                SECRET_KEY,
                f"{self.username}:{challenge}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Send authentication response
            auth_response = {
                'type': 'auth_response',
                'username': self.username,
                'hmac': hmac_response
            }
            self.client_socket.send(json.dumps(auth_response).encode())
            
            # Get authentication result
            result = json.loads(self.client_socket.recv(1024).decode())
            
            if result['status'] == 'success':
                print(f"[+] Authentication successful")
                
                # **FIX: Receive and display welcome message**
                welcome_data = self.client_socket.recv(4096).decode()
                welcome_msg = json.loads(welcome_data)
                if welcome_msg['type'] == 'welcome':
                    print(welcome_msg['message'])
                
                return True
            else:
                print(f"[-] Authentication failed: {result['message']}")
                return False
                
        except Exception as e:
            print(f"[-] Authentication error: {e}")
            return False
    
    def execute_command(self, command):
        """Send command to server and get result"""
        try:
            # Create command message
            command_msg = {
                'type': 'command',
                'command': command,
                'command_id': str(time.time()),
                'timestamp': datetime.now().isoformat()
            }
            
            # Send command
            self.client_socket.send(json.dumps(command_msg).encode())
            
            # Receive response
            response_data = self.client_socket.recv(8192).decode()
            response = json.loads(response_data)
            
            # Handle different response types
            if response['type'] == 'command_result':
                return response['output']
            elif response['type'] == 'welcome':
                return response['message']  # Handle welcome message
            else:
                return f"Unexpected response: {response}"
                
        except json.JSONDecodeError as e:
            return f"Error decoding server response: {e}\nRaw data: {response_data if 'response_data' in locals() else 'None'}"
        except Exception as e:
            return f"Error: {e}"
    
    def interactive_shell(self):
        """Interactive command shell"""
        print("\n" + "="*50)
        print("Secure Remote Command Shell")
        print("Type 'exit' to quit, 'help' for commands")
        print("="*50 + "\n")
        
        while True:
            try:
                # Get command
                command = input(f"{self.username}@remote> ").strip()
                
                if command.lower() == 'exit':
                    # Send exit message to server
                    exit_msg = {'type': 'exit'}
                    self.client_socket.send(json.dumps(exit_msg).encode())
                    break
                elif command.lower() == 'help':
                    # Help is handled by server
                    pass
                elif not command:
                    continue
                
                # Measure execution time
                start_time = time.time()
                
                # Execute command
                result = self.execute_command(command)
                
                # Calculate latency
                latency = time.time() - start_time
                
                # Display result
                print(result)
                print(f"\n[Command completed in {latency:.3f}s]")
                
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except Exception as e:
                print(f"Error: {e}")
    
    def close(self):
        """Close connection"""
        if hasattr(self, 'client_socket'):
            self.client_socket.close()
            print("[+] Connection closed")

def main():
    print("Secure Remote Command Client")
    print("-" * 30)
    
    # Get credentials
    username = input("Username: ").strip()
    password = input("Password: ").strip()  # Not used directly, but could be for key derivation
    
    # Create and connect client
    client = SecureCommandClient(username, password)
    
    if client.connect():
        if client.authenticate():
            client.interactive_shell()
        client.close()

if __name__ == "__main__":
    main()