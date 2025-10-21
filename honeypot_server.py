#!/usr/bin/env python3
"""
Honeypot Server - Main module
Simulates an SSH service to detect and log attack patterns
"""

import socket
import threading
import datetime
import json
import os
import logging
from logging.handlers import RotatingFileHandler
import ipaddress
import re
import time

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')

# Main logger for connection attempts
logger = logging.getLogger('honeypot')
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('logs/honeypot.log', maxBytes=10485760, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Separate logger for commands
cmd_logger = logging.getLogger('commands')
cmd_logger.setLevel(logging.INFO)
cmd_handler = RotatingFileHandler('logs/commands.log', maxBytes=10485760, backupCount=5)
cmd_handler.setFormatter(formatter)
cmd_logger.addHandler(cmd_handler)

# Default configuration
DEFAULT_CONFIG = {
    'ssh_port': 2222,  # Using non-standard port for safety
    'banner': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
    'max_connections': 10,
    'connection_timeout': 30,
    'log_dir': 'logs',
    'enable_commands': True,
    'fake_filesystem': True
}

# Load configuration or use defaults
def load_config():
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            # Merge with defaults for any missing keys
            for key, value in DEFAULT_CONFIG.items():
                if key not in config:
                    config[key] = value
            return config
    except (FileNotFoundError, json.JSONDecodeError):
        logger.warning("Config file not found or invalid. Using defaults.")
        return DEFAULT_CONFIG

config = load_config()

# Track connection attempts for fail2ban-like functionality
connection_attempts = {}

class HoneypotSSHServer:
    def __init__(self, host='0.0.0.0', port=config['ssh_port']):
        self.host = host
        self.port = port
        self.banner = config['banner']
        self.socket = None
        self.running = False
        self.connections = []
        self.fake_filesystem = {
            '/': ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'media', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var'],
            '/home': ['ubuntu'],
            '/home/ubuntu': ['.ssh', 'Documents', 'Downloads', '.bash_history'],
            '/etc': ['passwd', 'shadow', 'ssh', 'nginx', 'apache2'],
            '/var/log': ['auth.log', 'syslog', 'nginx']
        }
        self.current_dir = '/'

    def start(self):
        """Start the honeypot SSH server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(config['max_connections'])
            self.running = True
            logger.info(f"Honeypot SSH server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.socket.accept()
                    if len(self.connections) >= config['max_connections']:
                        client_socket.close()
                        continue
                        
                    # Log connection attempt
                    ip = client_address[0]
                    self.log_connection(ip)
                    
                    # Check if this IP should be blocked
                    if self.should_block(ip):
                        logger.warning(f"Blocking repeated connection attempts from {ip}")
                        client_socket.close()
                        continue
                    
                    # Handle connection in a new thread
                    client_thread = threading.Thread(target=self.handle_connection, args=(client_socket, client_address))
                    client_thread.daemon = True
                    client_thread.start()
                    self.connections.append(client_thread)
                    
                except socket.error as e:
                    if not self.running:
                        break
                    logger.error(f"Socket error: {e}")
                    
        except Exception as e:
            logger.error(f"Error starting server: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the honeypot SSH server"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("Honeypot SSH server stopped")

    def handle_connection(self, client_socket, address):
        """Handle client connection"""
        ip, port = address
        logger.info(f"Connection from {ip}:{port}")
        
        try:
            # Send SSH banner
            client_socket.send(f"{self.banner}\r\n".encode())
            
            # Wait for client identification
            data = client_socket.recv(1024)
            if not data:
                return
                
            client_banner = data.decode('utf-8', errors='ignore').strip()
            logger.info(f"Client banner: {client_banner}")
            
            # Simulate SSH key exchange
            client_socket.send(b"SSH-2.0-Key-Exchange\r\n")
            
            # Wait for username/password
            client_socket.send(b"login as: ")
            username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            logger.info(f"Login attempt with username: {username}")
            
            client_socket.send(b"Password: ")
            password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Log the credentials
            self.log_auth_attempt(ip, username, password)
            
            # Always fail authentication
            client_socket.send(b"Access denied\r\n")
            
            # If command simulation is enabled, allow a few failed attempts before "success"
            if config['enable_commands']:
                for _ in range(2):  # Simulate 2 more failed attempts
                    client_socket.send(b"login as: ")
                    username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                    client_socket.send(b"Password: ")
                    password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                    self.log_auth_attempt(ip, username, password)
                    client_socket.send(b"Access denied\r\n")
                
                # Now "succeed" to capture commands
                client_socket.send(b"login as: ")
                username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                client_socket.send(b"Password: ")
                password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                self.log_auth_attempt(ip, username, password)
                
                # Simulate successful login
                client_socket.send(f"Welcome to Ubuntu 20.04.5 LTS\r\n{username}@honeypot:~$ ".encode())
                
                # Handle commands
                self.handle_shell(client_socket, ip, username)
            
        except Exception as e:
            logger.error(f"Error handling connection: {e}")
        finally:
            client_socket.close()

    def handle_shell(self, client_socket, ip, username):
        """Simulate a shell to capture commands"""
        try:
            while True:
                command = b""
                while True:
                    char = client_socket.recv(1)
                    if not char:
                        return
                    
                    # Handle backspace
                    if char == b'\x7f' or char == b'\x08':
                        if command:
                            command = command[:-1]
                            client_socket.send(b"\b \b")  # Erase character
                        continue
                        
                    client_socket.send(char)  # Echo character
                    
                    # Handle enter key
                    if char == b'\r':
                        client_socket.send(b'\n')
                        break
                        
                    command += char
                
                cmd_str = command.decode('utf-8', errors='ignore').strip()
                if not cmd_str:
                    client_socket.send(f"{username}@honeypot:~$ ".encode())
                    continue
                
                # Log the command
                cmd_logger.info(f"IP: {ip}, User: {username}, Command: {cmd_str}")
                
                # Handle exit command
                if cmd_str.lower() in ('exit', 'logout', 'quit'):
                    client_socket.send(b"Connection closed\r\n")
                    break
                
                # Process command and send response
                response = self.process_command(cmd_str)
                client_socket.send(response.encode())
                client_socket.send(f"{username}@honeypot:~$ ".encode())
                
        except Exception as e:
            logger.error(f"Error in shell: {e}")

    def process_command(self, command):
        """Process shell commands and return fake responses"""
        cmd_parts = command.split()
        if not cmd_parts:
            return "\r\n"
            
        cmd = cmd_parts[0].lower()
        args = cmd_parts[1:] if len(cmd_parts) > 1 else []
        
        # Basic command simulation
        if cmd == "ls":
            path = args[0] if args else self.current_dir
            if path in self.fake_filesystem:
                return " ".join(self.fake_filesystem[path]) + "\r\n"
            return "ls: cannot access '" + path + "': No such file or directory\r\n"
            
        elif cmd == "cd":
            if not args:
                self.current_dir = "/"
                return "\r\n"
            path = args[0]
            if path in self.fake_filesystem:
                self.current_dir = path
                return "\r\n"
            return "cd: " + path + ": No such file or directory\r\n"
            
        elif cmd == "pwd":
            return self.current_dir + "\r\n"
            
        elif cmd == "cat":
            if not args:
                return "cat: missing operand\r\n"
            path = args[0]
            if path == "/etc/passwd":
                return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n...\r\n"
            elif path == "/etc/shadow":
                return "Permission denied\r\n"
            return "cat: " + path + ": No such file or directory\r\n"
            
        elif cmd == "uname":
            if "-a" in args:
                return "Linux honeypot 5.4.0-144-generic #161-Ubuntu SMP Fri Feb 3 14:49:04 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n"
            return "Linux\r\n"
            
        elif cmd == "whoami":
            return "ubuntu\r\n"
            
        elif cmd == "id":
            return "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)\r\n"
            
        elif cmd == "ps":
            return "  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 5678 pts/0    00:00:00 ps\r\n"
            
        elif cmd == "wget" or cmd == "curl":
            if not args:
                return f"{cmd}: missing URL\r\n"
            return f"{cmd}: Connecting...\nConnected.\nHTTP request sent, awaiting response... 200 OK\r\n"
            
        elif cmd == "chmod":
            return "\r\n"
            
        elif cmd == "rm":
            return "\r\n"
            
        elif cmd == "mkdir":
            return "\r\n"
            
        elif cmd == "touch":
            return "\r\n"
            
        # Default response for unknown commands
        return f"Command '{cmd}' not found\r\n"

    def log_connection(self, ip):
        """Log connection attempt and update tracking for fail2ban-like functionality"""
        timestamp = datetime.datetime.now()
        logger.info(f"Connection attempt from {ip}")
        
        # Update connection tracking
        if ip in connection_attempts:
            connection_attempts[ip].append(timestamp)
            # Keep only recent attempts (last hour)
            connection_attempts[ip] = [t for t in connection_attempts[ip] 
                                      if (timestamp - t).total_seconds() < 3600]
        else:
            connection_attempts[ip] = [timestamp]

    def log_auth_attempt(self, ip, username, password):
        """Log authentication attempt"""
        logger.info(f"Auth attempt - IP: {ip}, Username: {username}, Password: {password}")
        
        # Save to JSON for easier processing
        auth_log = {
            'timestamp': datetime.datetime.now().isoformat(),
            'ip': ip,
            'username': username,
            'password': password
        }
        
        with open(os.path.join(config['log_dir'], 'auth_attempts.json'), 'a') as f:
            f.write(json.dumps(auth_log) + '\n')

    def should_block(self, ip):
        """Determine if an IP should be blocked based on connection frequency"""
        if ip not in connection_attempts:
            return False
            
        # Block if more than 5 attempts in the last 5 minutes
        recent_attempts = [t for t in connection_attempts[ip] 
                          if (datetime.datetime.now() - t).total_seconds() < 300]
        
        return len(recent_attempts) > 5

def main():
    """Main function to start the honeypot server"""
    print("Starting Honeypot SSH Server...")
    server = HoneypotSSHServer()
    
    try:
        # Start server in a separate thread
        server_thread = threading.Thread(target=server.start)
        server_thread.daemon = True
        server_thread.start()
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down honeypot...")
        server.stop()

if __name__ == "__main__":
    main()