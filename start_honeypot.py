#!/usr/bin/env python3
"""
Honeypot Startup Script
-----------------------
This script starts all components of the honeypot system:
1. Honeypot SSH server
2. Dashboard web interface
3. Fail2ban integration
"""

import os
import sys
import json
import time
import subprocess
import threading
import argparse
from pathlib import Path

def load_config():
    """Load configuration from config.json"""
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}

def start_honeypot():
    """Start the honeypot SSH server"""
    print("[+] Starting honeypot SSH server...")
    honeypot_process = subprocess.Popen([sys.executable, 'honeypot_server.py'])
    return honeypot_process

def start_dashboard():
    """Start the dashboard web interface"""
    print("[+] Starting dashboard web interface...")
    dashboard_process = subprocess.Popen([sys.executable, 'dashboard.py'])
    return dashboard_process

def start_fail2ban():
    """Start the fail2ban integration"""
    print("[+] Starting fail2ban integration...")
    fail2ban_process = subprocess.Popen([sys.executable, 'fail2ban_integration.py'])
    return fail2ban_process

def ensure_directories():
    """Ensure all required directories exist"""
    directories = ['logs', 'templates', 'static', 'reports']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)

def main():
    parser = argparse.ArgumentParser(description='Start the honeypot system')
    parser.add_argument('--honeypot-only', action='store_true', help='Start only the honeypot server')
    parser.add_argument('--dashboard-only', action='store_true', help='Start only the dashboard')
    parser.add_argument('--fail2ban-only', action='store_true', help='Start only the fail2ban integration')
    args = parser.parse_args()

    # Ensure directories exist
    ensure_directories()
    
    # Load configuration
    config = load_config()
    
    processes = []
    
    try:
        # Start components based on arguments
        if args.honeypot_only:
            processes.append(start_honeypot())
        elif args.dashboard_only:
            processes.append(start_dashboard())
        elif args.fail2ban_only:
            processes.append(start_fail2ban())
        else:
            # Start all components
            processes.append(start_honeypot())
            time.sleep(1)  # Give honeypot time to start
            processes.append(start_dashboard())
            processes.append(start_fail2ban())
            
        print("\n[+] All components started successfully!")
        print("[+] Honeypot SSH server running on port", config.get("ssh_port", 2222))
        print("[+] Dashboard web interface available at http://localhost:5000")
        print("[+] Press Ctrl+C to stop all services\n")
        
        # Keep the script running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[!] Shutting down honeypot system...")
        for process in processes:
            process.terminate()
        print("[+] All components stopped")

if __name__ == "__main__":
    main()