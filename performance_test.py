import time
import threading
import statistics
import subprocess
import socket
import json
import ssl
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor
import numpy as np

class PerformanceTester:
    def __init__(self):
        self.secure_latencies = []
        self.insecure_latencies = []
        self.throughput_results = {}
        
    def test_secure_server(self, num_requests=50):
        """Test secure server performance"""
        print("\n[*] Testing SECURE server...")
        
        # Test latency
        latencies = []
        for i in range(num_requests):
            try:
                start = time.time()
                
                # Create secure connection
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                secure_sock = context.wrap_socket(sock, server_hostname='localhost')
                secure_sock.connect(('localhost', 8888))
                
                # Skip auth for performance test (or implement minimal auth)
                secure_sock.close()
                
                latency = time.time() - start
                latencies.append(latency)
                
            except Exception as e:
                print(f"Error: {e}")
                
        self.secure_latencies = latencies
        print(f"Secure Server - Avg Latency: {statistics.mean(latencies)*1000:.2f}ms")
        
    def test_insecure_server(self, num_requests=50):
        """Test insecure server performance (for comparison)"""
        print("\n[*] Testing INSECURE server (baseline)...")
        
        # You'll need to run a simple insecure server for this test
        latencies = []
        for i in range(num_requests):
            try:
                start = time.time()
                
                # Simple TCP connection (no SSL)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(('localhost', 8889))  # Use different port for insecure server
                sock.close()
                
                latency = time.time() - start
                latencies.append(latency)
                
            except Exception as e:
                print(f"Error: {e}")
                
        self.insecure_latencies = latencies
        print(f"Insecure Server - Avg Latency: {statistics.mean(latencies)*1000:.2f}ms")
    
    def test_throughput(self, num_clients=10, commands_per_client=10):
        """Test system throughput under load"""
        print(f"\n[*] Testing throughput with {num_clients} clients...")
        
        def client_worker(client_id):
            latencies = []
            try:
                # Connect to secure server
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                secure_sock = context.wrap_socket(sock, server_hostname='localhost')
                secure_sock.connect(('localhost', 8888))
                
                # Skip auth for throughput test
                
                for cmd_num in range(commands_per_client):
                    start = time.time()
                    
                    # Send command
                    command = {'type': 'command', 'command': 'echo test'}
                    secure_sock.send(json.dumps(command).encode())
                    
                    # Receive response
                    response = secure_sock.recv(4096)
                    
                    latency = time.time() - start
                    latencies.append(latency)
                    
                secure_sock.close()
                
            except Exception as e:
                print(f"Client {client_id} error: {e}")
                
            return latencies
        
        # Run clients concurrently
        all_latencies = []
        with ThreadPoolExecutor(max_workers=num_clients) as executor:
            futures = [executor.submit(client_worker, i) for i in range(num_clients)]
            for future in futures:
                all_latencies.extend(future.result())
        
        # Calculate throughput
        total_commands = num_clients * commands_per_client
        total_time = sum(all_latencies)
        
        self.throughput_results = {
            'total_commands': total_commands,
            'avg_latency': statistics.mean(all_latencies) if all_latencies else 0,
            'throughput': total_commands / total_time if total_time > 0 else 0,
            'p95_latency': np.percentile(all_latencies, 95) if all_latencies else 0
        }
        
        print(f"Total commands executed: {total_commands}")
        print(f"Average latency: {self.throughput_results['avg_latency']*1000:.2f}ms")
        print(f"Throughput: {self.throughput_results['throughput']:.2f} commands/second")
        print(f"95th percentile latency: {self.throughput_results['p95_latency']*1000:.2f}ms")
    
    def generate_report(self):
        """Generate performance analysis report"""
        print("\n" + "="*60)
        print("PERFORMANCE OVERHEAD ANALYSIS REPORT")
        print("="*60)
        
        if self.secure_latencies and self.insecure_latencies:
            secure_avg = statistics.mean(self.secure_latencies)
            insecure_avg = statistics.mean(self.insecure_latencies)
            overhead = ((secure_avg - insecure_avg) / insecure_avg) * 100
            
            print(f"\n1. Latency Comparison:")
            print(f"   - Insecure (baseline): {insecure_avg*1000:.2f}ms")
            print(f"   - Secure: {secure_avg*1000:.2f}ms")
            print(f"   - Overhead: +{overhead:.1f}%")
        
        if self.throughput_results:
            print(f"\n2. Throughput Analysis:")
            print(f"   - Commands/second: {self.throughput_results['throughput']:.2f}")
            print(f"   - Average latency under load: {self.throughput_results['avg_latency']*1000:.2f}ms")
            print(f"   - P95 latency: {self.throughput_results['p95_latency']*1000:.2f}ms")
        
        print("\n3. Security Overhead Factors:")
        print("   - SSL/TLS handshake (connection establishment)")
        print("   - Encryption/decryption of data")
        print("   - Authentication challenge-response")
        print("   - Audit logging I/O operations")
        
        print("\n4. Recommendations:")
        print("   - Use connection pooling to reduce handshake overhead")
        print("   - Implement command batching for multiple commands")
        print("   - Consider lighter encryption for LAN environments")
        print("   - Async I/O for better throughput")
        
        # Create visualization
        self.create_plots()
    
    def create_plots(self):
        """Create performance visualization plots"""
        try:
            fig, axes = plt.subplots(1, 2, figsize=(12, 5))
            
            # Latency comparison plot
            if self.secure_latencies and self.insecure_latencies:
                axes[0].hist([self.insecure_latencies, self.secure_latencies], 
                            label=['Insecure', 'Secure'], 
                            bins=20, alpha=0.7)
                axes[0].set_xlabel('Latency (seconds)')
                axes[0].set_ylabel('Frequency')
                axes[0].set_title('Latency Distribution Comparison')
                axes[0].legend()
            
            # Throughput plot
            if self.throughput_results:
                labels = ['Avg Latency', 'P95 Latency']
                values = [self.throughput_results['avg_latency']*1000, 
                         self.throughput_results['p95_latency']*1000]
                
                axes[1].bar(labels, values, color=['blue', 'orange'])
                axes[1].set_ylabel('Latency (ms)')
                axes[1].set_title('Throughput Test Latencies')
                
                # Add throughput text
                axes[1].text(0.5, 0.9, 
                            f"Throughput: {self.throughput_results['throughput']:.1f} cmd/s",
                            transform=axes[1].transAxes,
                            bbox=dict(boxstyle="round,pad=0.3", facecolor="yellow"))
            
            plt.tight_layout()
            plt.savefig('performance_analysis.png')
            print("\n[+] Performance plots saved to 'performance_analysis.png'")
            
        except Exception as e:
            print(f"Could not create plots: {e}")

def run_insecure_test_server():
    """Simple insecure server for baseline testing"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 8889))
    server.listen(1)
    
    print("[*] Insecure test server running on port 8889")
    
    while True:
        client, addr = server.accept()
        client.close()

if __name__ == "__main__":
    tester = PerformanceTester()
    
    # Run tests
    tester.test_secure_server(30)
    
    # Note: You need to run an insecure server separately on port 8889
    # Uncomment the next line if you want to test insecure server
    # tester.test_insecure_server(30)
    
    tester.test_throughput(num_clients=5, commands_per_client=10)
    tester.generate_report()