# Secure Remote Command Execution System

## Project Overview
A secure client-server system that allows authenticated clients to execute system commands remotely over SSL/TLS encrypted connections. The system supports multiple concurrent clients and provides comprehensive audit logging.

## Team Members & Roles

| Member | Role | Responsibilities | Code Files |
|--------|------|-----------------|------------|
| **YELLAPANTULA VENKATA PRATEEK SRN:PES2UG24CS617** | Server & Security Developer | Server architecture, SSL/TLS implementation, Multi-threading, Command execution engine, Security features | `server.py`, Certificate generation |
| **NARENDRA J KATHARE SRN:PES2UG25CS814** | Client & Protocol Developer | Client implementation, Protocol design (JSON), Authentication mechanism, User interface, Command parsing | `client.py`, Protocol definitions |
| **VENKATESH SRN:PES2UG24CS580** | Testing & Documentation Lead | Performance testing, Audit logging, GitHub repository, Documentation, Edge case testing | `performance_test.py`, `requirements.txt`, `README.md` |

### Detailed Responsibilities

#### YELLAPANTULA VENKATA PRATEEK SRN:PES2UG24CS617 - Server & Security Developer
- Implement TCP socket server with multi-threading
- Setup SSL/TLS encryption and certificate generation
- Implement challenge-response authentication (HMAC)
- Create secure command execution engine
- Prevent command injection attacks
- Handle multiple concurrent clients
- Implement dangerous command blacklisting

#### NARENDRA J KATHARE SRN:PES2UG25CS814 - Client & Protocol Developer
- Implement TCP client with SSL/TLS connection
- Design JSON-based communication protocol
- Implement HMAC authentication on client side
- Create interactive command shell
- Handle user input and display outputs
- Implement help menu and command suggestions
- Cross-platform command mapping (Windows/Linux)

#### VENKATESH SRN:PES2UG24CS580 - Testing & Documentation Lead
- Create performance testing suite
- Measure connection latency and command throughput
- Test scalability with multiple clients
- Implement audit logging system
- Create GitHub repository with documentation
- Write README and setup instructions
- Test edge cases and error handling

## Features
- SSL/TLS encrypted communication (Member A)
- Challenge-response HMAC authentication (Member B)
- Multi-client support with threading (Member A)
- Structured JSON protocol (Member B)
- Comprehensive audit logging (Member C)
- Command injection prevention (Member A)
- Performance testing suite (Member C)
- Cross-platform support (Member B)

## Requirements
- Python 3.7 or higher
- pyOpenSSL library

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/secure-remote-command.git
cd secure-remote-command
