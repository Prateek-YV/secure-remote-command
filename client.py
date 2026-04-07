import socket
import ssl
import json
import hmac
import hashlib
import time
import sys

# Configuration - CHANGE THIS FOR MULTIPLE LAPTOPS
SERVER_HOST = 'localhost'  # Change to server's IP address (e.g., '192.168.1.100')
SERVER_PORT = 8888
SECRET_KEY = b'super_secret_key_123'

class SecureClient:
    def __init__(self, username):
        self.username = username
        self.client_socket = None
        
        # SSL context
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
    
    def connect(self):
        """Connect to server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            self.client_socket = self.context.wrap_socket(sock, server_hostname=SERVER_HOST)
            self.client_socket.connect((SERVER_HOST, SERVER_PORT))
            print(f"[+] Connected to {SERVER_HOST}:{SERVER_PORT}")
            return True
        except ConnectionRefusedError:
            print("[-] Connection refused. Is server running?")
            return False
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False
    
    def authenticate(self):
        """Authenticate with server"""
        try:
            # Receive challenge
            data = self.client_socket.recv(1024).decode()
            challenge_msg = json.loads(data)
            
            if challenge_msg.get('type') != 'auth_challenge':
                print("[-] Invalid challenge")
                return False
            
            challenge = challenge_msg['challenge']
            
            # Compute HMAC
            hmac_val = hmac.new(
                SECRET_KEY,
                f"{self.username}:{challenge}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Send response
            response = {
                'type': 'auth_response',
                'username': self.username,
                'hmac': hmac_val
            }
            self.client_socket.send(json.dumps(response).encode())
            
            # Get result
            result = json.loads(self.client_socket.recv(1024).decode())
            
            if result.get('status') == 'success':
                print("[+] Authentication successful")
                
                # Receive welcome message
                welcome = json.loads(self.client_socket.recv(4096).decode())
                if welcome.get('type') == 'welcome':
                    print(welcome['message'])
                return True
            else:
                print(f"[-] Auth failed: {result.get('message')}")
                return False
                
        except Exception as e:
            print(f"[-] Auth error: {e}")
            return False
    
    def execute_command(self, command):
        """Send command and get result"""
        try:
            cmd_msg = {
                'type': 'command',
                'command': command,
                'command_id': str(time.time())
            }
            self.client_socket.send(json.dumps(cmd_msg).encode())
            
            response = json.loads(self.client_socket.recv(8192).decode())
            
            if response.get('type') == 'command_result':
                return response.get('output', 'No output')
            else:
                return f"Unexpected: {response}"
                
        except Exception as e:
            return f"Error: {e}"
    
    def show_help(self):
        """Display comprehensive help menu"""
        help_text = """
================================================================================
                         AVAILABLE COMMANDS
================================================================================

FILE OPERATIONS:
--------------------------------------------------------------------------------
  dir / ls              - List files in current directory
  cd                    - Show current directory path
  type <filename>       - View contents of a file
  echo <text> > file    - Create file with text
  echo <text> >> file   - Append text to existing file
  del <filename>        - Delete a file
  mkdir <dirname>       - Create a new directory
  rmdir <dirname>       - Remove an empty directory
  copy <src> <dest>     - Copy a file
  ren <old> <new>       - Rename a file

SYSTEM INFORMATION:
--------------------------------------------------------------------------------
  whoami                - Show current username
  ipconfig              - Show network configuration
  hostname              - Show computer name
  date /t               - Show current date
  time /t               - Show current time
  ver                   - Show Windows version
  tasklist              - Show running processes

NETWORK COMMANDS:
--------------------------------------------------------------------------------
  ping <host>           - Test network connection
  netstat -an           - Show network connections

TEXT PROCESSING:
--------------------------------------------------------------------------------
  findstr <text> <file> - Search for text in files
  echo <text>           - Display text

PROCESS MANAGEMENT:
--------------------------------------------------------------------------------
  tasklist              - List running processes
  taskkill /PID <id>    - Kill a process by ID

================================================================================
EXAMPLES:
--------------------------------------------------------------------------------
  List files:           dir
  Create file:          echo Hello World > myfile.txt
  View file:            type myfile.txt
  Append to file:       echo New line >> myfile.txt
  Delete file:          del myfile.txt
  Create folder:        mkdir testfolder
  Network info:         ipconfig
  Current user:         whoami
  Search in file:       findstr "error" server.py
================================================================================
"""
        print(help_text)
    
    def run(self):
        """Main client loop"""
        if not self.connect():
            return
        
        if not self.authenticate():
            self.client_socket.close()
            return
        
        print("\nType 'help' for complete command list, 'exit' to quit\n")
        
        while True:
            try:
                cmd = input(f"{self.username}@remote> ").strip()
                
                if cmd.lower() == 'exit':
                    break
                elif cmd.lower() == 'help':
                    self.show_help()
                    continue
                elif cmd.lower() == 'clear' or cmd.lower() == 'cls':
                    print("\n" * 50)
                    continue
                elif not cmd:
                    continue
                
                start = time.time()
                result = self.execute_command(cmd)
                elapsed = (time.time() - start) * 1000
                
                print(result)
                if result and not result.startswith("ERROR"):
                    print(f"\n[Time: {elapsed:.2f}ms]")
                print()
                
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except Exception as e:
                print(f"Error: {e}")
                break
        
        self.client_socket.close()
        print("[+] Disconnected")

def main():
    print("="*60)
    print("     SECURE REMOTE COMMAND EXECUTION SYSTEM")
    print("="*60)
    print()
    
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    
    client = SecureClient(username)
    client.run()

if __name__ == "__main__":
    main()
