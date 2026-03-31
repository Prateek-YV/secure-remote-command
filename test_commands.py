import subprocess
import os
import shlex

def test_command(cmd):
    """Test if a command works on your system"""
    print(f"\nTesting: {cmd}")
    print("-" * 40)
    
    try:
        if os.name == 'nt':  # Windows
            # Test with cmd /c
            result = subprocess.run(
                ['cmd', '/c'] + shlex.split(cmd, posix=False),
                capture_output=True,
                text=True,
                timeout=5,
                shell=False
            )
        else:  # Linux
            result = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                text=True,
                timeout=5,
                shell=False
            )
        
        if result.returncode == 0:
            print("✅ SUCCESS!")
            print(f"Output: {result.stdout[:200]}...")
        else:
            print("❌ FAILED")
            print(f"Error: {result.stderr}")
            
    except Exception as e:
        print(f"❌ ERROR: {e}")

print("=" * 60)
print("TESTING AVAILABLE COMMANDS ON YOUR SYSTEM")
print("=" * 60)
print(f"Operating System: {'Windows' if os.name == 'nt' else 'Linux/Mac'}")

# Test common commands
commands_to_test = [
    'dir',
    'date /t',
    'time /t',
    'ipconfig',
    'whoami',
    'hostname',
    'ver',
    'echo Hello World',
    'cd',
    'tasklist'
]

for cmd in commands_to_test:
    test_command(cmd)

print("\n" + "=" * 60)
print("If most commands show ✅ SUCCESS, the server will work!")
print("If many show ❌ FAILED, we need to troubleshoot further")