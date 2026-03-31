import socket
import subprocess
import threading

def handle_client(client_socket, addr):
    """Handle client without any security"""
    print(f"[Insecure] Connection from {addr}")
    
    while True:
        try:
            data = client_socket.recv(4096).decode()
            if not data:
                break
            
            # Execute command (INSECURE - direct shell execution)
            # WARNING: This is intentionally insecure for testing only!
            result = subprocess.getoutput(data)
            
            client_socket.send(result.encode())
            
        except Exception as e:
            print(f"Error: {e}")
            break
    
    client_socket.close()

def start_insecure_server():
    """Start insecure server on port 8889"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('localhost', 8889))
    server.listen(5)
    
    print("[*] INSECURE server running on port 8889 (for baseline testing)")
    print("[!] WARNING: This server has NO security - DO NOT USE IN PRODUCTION!")
    
    while True:
        client, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client, addr))
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    start_insecure_server()