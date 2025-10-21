#!/usr/bin/env python3
"""
Fail2Ban Integration for Honeypot
Processes honeypot logs and updates fail2ban to block malicious IPs
"""

import os
import re
import json
import time
import subprocess
import logging
import argparse
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='logs/fail2ban_integration.log'
)
logger = logging.getLogger('fail2ban_integration')

class Fail2BanIntegration:
    def __init__(self, log_dir='logs', threshold=5, ban_time=3600):
        """
        Initialize the Fail2Ban integration
        
        Args:
            log_dir: Directory containing honeypot logs
            threshold: Number of attempts before banning
            ban_time: Ban duration in seconds
        """
        self.log_dir = log_dir
        self.threshold = threshold
        self.ban_time = ban_time
        self.auth_log_file = os.path.join(log_dir, 'auth_attempts.json')
        self.banned_ips_file = os.path.join(log_dir, 'banned_ips.json')
        self.honeypot_log_file = os.path.join(log_dir, 'honeypot.log')
        
        # Create logs directory if it doesn't exist
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Load or create banned IPs file
        self.banned_ips = self.load_banned_ips()
        
    def load_banned_ips(self):
        """Load the list of banned IPs from file"""
        if os.path.exists(self.banned_ips_file):
            try:
                with open(self.banned_ips_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.error("Error parsing banned IPs file. Creating new one.")
                return {}
        return {}
        
    def save_banned_ips(self):
        """Save the list of banned IPs to file"""
        with open(self.banned_ips_file, 'w') as f:
            json.dump(self.banned_ips, f, indent=2)
            
    def load_auth_attempts(self):
        """Load authentication attempts from JSON log file"""
        attempts = []
        if os.path.exists(self.auth_log_file):
            with open(self.auth_log_file, 'r') as f:
                for line in f:
                    try:
                        attempt = json.loads(line.strip())
                        attempts.append(attempt)
                    except json.JSONDecodeError:
                        continue
        return attempts
        
    def parse_honeypot_log(self):
        """Parse the honeypot log file for connection attempts"""
        connection_attempts = {}
        
        if not os.path.exists(self.honeypot_log_file):
            return connection_attempts
            
        with open(self.honeypot_log_file, 'r') as f:
            for line in f:
                # Look for connection attempt log entries
                match = re.search(r'Connection attempt from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})', line)
                    if timestamp_match:
                        timestamp = datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S,%f')
                        
                        if ip in connection_attempts:
                            connection_attempts[ip].append(timestamp)
                        else:
                            connection_attempts[ip] = [timestamp]
        
        return connection_attempts
        
    def identify_attackers(self):
        """Identify IPs that should be banned based on connection frequency"""
        # Get connection attempts from log
        connection_attempts = self.parse_honeypot_log()
        
        # Get authentication attempts
        auth_attempts = self.load_auth_attempts()
        
        # Combine data for analysis
        ip_data = {}
        
        # Process connection attempts
        for ip, timestamps in connection_attempts.items():
            if ip not in ip_data:
                ip_data[ip] = {'connections': 0, 'auth_attempts': 0}
            ip_data[ip]['connections'] = len(timestamps)
        
        # Process authentication attempts
        for attempt in auth_attempts:
            ip = attempt['ip']
            if ip not in ip_data:
                ip_data[ip] = {'connections': 0, 'auth_attempts': 0}
            ip_data[ip]['auth_attempts'] += 1
        
        # Identify IPs to ban
        ips_to_ban = []
        now = datetime.now()
        
        for ip, data in ip_data.items():
            # Skip already banned IPs
            if ip in self.banned_ips:
                ban_time = datetime.fromisoformat(self.banned_ips[ip]['timestamp'])
                ban_duration = timedelta(seconds=self.banned_ips[ip]['duration'])
                
                # If ban has expired, remove from banned list
                if now > ban_time + ban_duration:
                    logger.info(f"Ban expired for IP: {ip}")
                    del self.banned_ips[ip]
                else:
                    continue
            
            # Ban if exceeds threshold
            total_attempts = data['connections'] + data['auth_attempts']
            if total_attempts >= self.threshold:
                ips_to_ban.append(ip)
                
        return ips_to_ban
        
    def ban_ip(self, ip):
        """Ban an IP using iptables or Windows Firewall"""
        if ip in self.banned_ips:
            logger.info(f"IP {ip} is already banned")
            return
            
        try:
            # Detect OS and use appropriate command
            if os.name == 'nt':  # Windows
                # Use Windows Firewall
                rule_name = f"HoneypotBlock_{ip.replace('.', '_')}"
                cmd = [
                    'powershell', 
                    '-Command', 
                    f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -Action Block -RemoteAddress {ip}"
                ]
                subprocess.run(cmd, check=True)
                logger.info(f"Banned IP {ip} using Windows Firewall")
            else:  # Linux/Unix
                # Use iptables
                cmd = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
                subprocess.run(cmd, check=True)
                logger.info(f"Banned IP {ip} using iptables")
                
            # Record the ban
            self.banned_ips[ip] = {
                'timestamp': datetime.now().isoformat(),
                'duration': self.ban_time,
                'reason': f"Exceeded threshold with {self.threshold}+ attempts"
            }
            self.save_banned_ips()
            
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to ban IP {ip}: {e}")
            
    def unban_ip(self, ip):
        """Remove IP ban"""
        if ip not in self.banned_ips:
            logger.info(f"IP {ip} is not banned")
            return
            
        try:
            # Detect OS and use appropriate command
            if os.name == 'nt':  # Windows
                # Use Windows Firewall
                rule_name = f"HoneypotBlock_{ip.replace('.', '_')}"
                cmd = [
                    'powershell', 
                    '-Command', 
                    f"Remove-NetFirewallRule -DisplayName '{rule_name}'"
                ]
                subprocess.run(cmd, check=True)
                logger.info(f"Unbanned IP {ip} from Windows Firewall")
            else:  # Linux/Unix
                # Use iptables
                cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
                subprocess.run(cmd, check=True)
                logger.info(f"Unbanned IP {ip} from iptables")
                
            # Remove from banned list
            del self.banned_ips[ip]
            self.save_banned_ips()
            
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to unban IP {ip}: {e}")
            
    def check_expired_bans(self):
        """Check for and remove expired bans"""
        now = datetime.now()
        expired_ips = []
        
        for ip, ban_info in self.banned_ips.items():
            ban_time = datetime.fromisoformat(ban_info['timestamp'])
            ban_duration = timedelta(seconds=ban_info['duration'])
            
            if now > ban_time + ban_duration:
                expired_ips.append(ip)
                
        for ip in expired_ips:
            logger.info(f"Ban expired for IP: {ip}")
            self.unban_ip(ip)
            
    def run(self):
        """Run the fail2ban integration process"""
        logger.info("Starting fail2ban integration process")
        
        # Check for expired bans
        self.check_expired_bans()
        
        # Identify IPs to ban
        ips_to_ban = self.identify_attackers()
        
        # Ban new IPs
        for ip in ips_to_ban:
            self.ban_ip(ip)
            
        logger.info(f"Fail2ban integration completed. {len(ips_to_ban)} new IPs banned.")
        
def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Fail2Ban Integration for Honeypot')
    parser.add_argument('--threshold', type=int, default=5, help='Number of attempts before banning')
    parser.add_argument('--ban-time', type=int, default=3600, help='Ban duration in seconds')
    parser.add_argument('--log-dir', type=str, default='logs', help='Directory containing honeypot logs')
    args = parser.parse_args()
    
    # Create fail2ban integration
    f2b = Fail2BanIntegration(
        log_dir=args.log_dir,
        threshold=args.threshold,
        ban_time=args.ban_time
    )
    
    # Run once
    f2b.run()
    
    # If running as a service, uncomment this to run continuously
    """
    while True:
        f2b.run()
        time.sleep(60)  # Check every minute
    """

if __name__ == "__main__":
    main()