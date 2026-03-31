# Secure Remote Command Execution System

A secure client-server system that allows authenticated clients to execute commands remotely over SSL/TLS encrypted connections.

## Features

- **SSL/TLS Encryption** - All communication encrypted
- **Challenge-Response Authentication** - HMAC-based authentication
- **Multi-Client Support** - Handles multiple concurrent clients
- **Audit Logging** - Complete log of all activities
- **Command Security** - Prevents command injection attacks

## Requirements

- Python 3.7+
- OpenSSL
- Dependencies: `pip install -r requirements.txt`

## Quick Start

### Start Server
```bash
python server.py
