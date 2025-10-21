#!/usr/bin/env python3
"""
Log Analyzer for Honeypot Server
Processes logs to extract insights about attack patterns
"""

import os
import json
import re
import datetime
import pandas as pd
import geoip2.database
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter, defaultdict

class HoneypotLogAnalyzer:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        self.auth_attempts_file = os.path.join(log_dir, 'auth_attempts.json')
        self.honeypot_log_file = os.path.join(log_dir, 'honeypot.log')
        self.commands_log_file = os.path.join(log_dir, 'commands.log')
        
        # Ensure GeoIP database exists
        self.geoip_db = 'GeoLite2-City.mmdb'
        if not os.path.exists(self.geoip_db):
            print(f"Warning: GeoIP database not found at {self.geoip_db}")
            print("Download it from MaxMind or use the update_geoip.py script")
        
    def load_auth_attempts(self):
        """Load authentication attempts from JSON log file"""
        attempts = []
        if os.path.exists(self.auth_attempts_file):
            with open(self.auth_attempts_file, 'r') as f:
                for line in f:
                    try:
                        attempt = json.loads(line.strip())
                        attempts.append(attempt)
                    except json.JSONDecodeError:
                        continue
        return attempts
    
    def parse_log_file(self, log_file):
        """Parse a log file and extract relevant information"""
        log_entries = []
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                for line in f:
                    # Parse log line based on format
                    match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\w+) - (\w+) - (.*)', line)
                    if match:
                        timestamp, logger_name, level, message = match.groups()
                        log_entries.append({
                            'timestamp': timestamp,
                            'logger': logger_name,
                            'level': level,
                            'message': message
                        })
        return log_entries
    
    def extract_commands(self):
        """Extract commands from command log file"""
        commands = []
        log_entries = self.parse_log_file(self.commands_log_file)
        
        for entry in log_entries:
            # Extract IP, username, and command from log message
            match = re.match(r'IP: ([\d\.]+), User: (.*), Command: (.*)', entry['message'])
            if match:
                ip, username, command = match.groups()
                commands.append({
                    'timestamp': entry['timestamp'],
                    'ip': ip,
                    'username': username,
                    'command': command
                })
        
        return commands
    
    def get_ip_locations(self, ips):
        """Get geolocation data for a list of IPs"""
        locations = {}
        
        if not os.path.exists(self.geoip_db):
            return locations
            
        try:
            with geoip2.database.Reader(self.geoip_db) as reader:
                for ip in ips:
                    try:
                        response = reader.city(ip)
                        locations[ip] = {
                            'country': response.country.name,
                            'country_iso': response.country.iso_code,
                            'city': response.city.name,
                            'latitude': response.location.latitude,
                            'longitude': response.location.longitude
                        }
                    except Exception:
                        # IP not found in database
                        locations[ip] = {
                            'country': 'Unknown',
                            'country_iso': 'XX',
                            'city': 'Unknown',
                            'latitude': 0,
                            'longitude': 0
                        }
        except Exception as e:
            print(f"Error loading GeoIP database: {e}")
            
        return locations
    
    def analyze_auth_attempts(self):
        """Analyze authentication attempts"""
        attempts = self.load_auth_attempts()
        
        if not attempts:
            return {
                'total_attempts': 0,
                'unique_ips': 0,
                'top_usernames': [],
                'top_passwords': [],
                'attempts_by_day': {}
            }
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(attempts)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['date'] = df['timestamp'].dt.date
        
        # Basic statistics
        unique_ips = df['ip'].nunique()
        top_usernames = df['username'].value_counts().head(10).to_dict()
        top_passwords = df['password'].value_counts().head(10).to_dict()
        
        # Attempts by day
        attempts_by_day = df.groupby('date').size().to_dict()
        attempts_by_day = {str(k): v for k, v in attempts_by_day.items()}
        
        return {
            'total_attempts': len(attempts),
            'unique_ips': unique_ips,
            'top_usernames': top_usernames,
            'top_passwords': top_passwords,
            'attempts_by_day': attempts_by_day
        }
    
    def analyze_commands(self):
        """Analyze executed commands"""
        commands = self.extract_commands()
        
        if not commands:
            return {
                'total_commands': 0,
                'unique_ips': 0,
                'top_commands': [],
                'command_categories': {}
            }
        
        # Convert to DataFrame
        df = pd.DataFrame(commands)
        
        # Basic statistics
        unique_ips = df['ip'].nunique()
        top_commands = df['command'].value_counts().head(10).to_dict()
        
        # Categorize commands
        def categorize_command(cmd):
            cmd_lower = cmd.lower().split()[0]
            if cmd_lower in ['ls', 'cd', 'pwd', 'cat', 'less', 'more']:
                return 'File System Navigation'
            elif cmd_lower in ['wget', 'curl', 'ftp', 'scp', 'rsync']:
                return 'File Transfer'
            elif cmd_lower in ['ps', 'top', 'kill', 'pkill', 'service', 'systemctl']:
                return 'Process Management'
            elif cmd_lower in ['apt', 'apt-get', 'yum', 'dnf', 'pacman', 'brew']:
                return 'Package Management'
            elif cmd_lower in ['ifconfig', 'ip', 'netstat', 'ss', 'ping', 'traceroute']:
                return 'Network Commands'
            elif cmd_lower in ['chmod', 'chown', 'useradd', 'userdel', 'groupadd']:
                return 'System Administration'
            else:
                return 'Other'
        
        df['category'] = df['command'].apply(categorize_command)
        command_categories = df['category'].value_counts().to_dict()
        
        return {
            'total_commands': len(commands),
            'unique_ips': unique_ips,
            'top_commands': top_commands,
            'command_categories': command_categories
        }
    
    def generate_ip_map(self):
        """Generate a world map of attack origins"""
        attempts = self.load_auth_attempts()
        
        if not attempts:
            return None
            
        # Get unique IPs
        ips = list(set(a['ip'] for a in attempts))
        
        # Get geolocation data
        locations = self.get_ip_locations(ips)
        
        # Count attempts by location
        location_counts = defaultdict(int)
        for attempt in attempts:
            ip = attempt['ip']
            if ip in locations:
                country = locations[ip]['country']
                location_counts[country] += 1
        
        # Prepare data for choropleth map
        countries = []
        counts = []
        for country, count in location_counts.items():
            countries.append(country)
            counts.append(count)
        
        # Create map
        if not countries:
            return None
            
        fig = px.choropleth(
            locations=[locations[ip]['country_iso'] for ip in ips if ip in locations and locations[ip]['country_iso'] != 'XX'],
            color=[location_counts[locations[ip]['country']] for ip in ips if ip in locations and locations[ip]['country_iso'] != 'XX'],
            hover_name=[locations[ip]['country'] for ip in ips if ip in locations and locations[ip]['country_iso'] != 'XX'],
            color_continuous_scale=px.colors.sequential.Plasma,
            title='Attack Origins by Country'
        )
        
        return fig
    
    def generate_time_series(self):
        """Generate time series of attack attempts"""
        attempts = self.load_auth_attempts()
        
        if not attempts:
            return None
            
        # Convert to DataFrame
        df = pd.DataFrame(attempts)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['date'] = df['timestamp'].dt.date
        
        # Group by date
        attempts_by_date = df.groupby('date').size().reset_index(name='count')
        
        # Create time series plot
        fig = px.line(
            attempts_by_date, 
            x='date', 
            y='count',
            title='Authentication Attempts Over Time'
        )
        
        return fig
    
    def generate_command_pie(self):
        """Generate pie chart of command categories"""
        command_stats = self.analyze_commands()
        
        if not command_stats['command_categories']:
            return None
            
        # Create pie chart
        labels = list(command_stats['command_categories'].keys())
        values = list(command_stats['command_categories'].values())
        
        fig = px.pie(
            names=labels,
            values=values,
            title='Command Categories'
        )
        
        return fig
    
    def generate_report(self, output_dir='reports'):
        """Generate a comprehensive report of honeypot activity"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Get analysis data
        auth_stats = self.analyze_auth_attempts()
        command_stats = self.analyze_commands()
        
        # Generate timestamp
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Create HTML report
        html_report = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Honeypot Activity Report - {timestamp}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #333; }}
                .stats-container {{ display: flex; flex-wrap: wrap; }}
                .stat-box {{ 
                    background-color: #f5f5f5; 
                    border-radius: 5px; 
                    padding: 15px; 
                    margin: 10px; 
                    flex: 1; 
                    min-width: 200px;
                }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
            </style>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        </head>
        <body>
            <h1>Honeypot Activity Report</h1>
            <p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h2>Authentication Attempts</h2>
            <div class="stats-container">
                <div class="stat-box">
                    <h3>Total Attempts</h3>
                    <p>{auth_stats['total_attempts']}</p>
                </div>
                <div class="stat-box">
                    <h3>Unique IPs</h3>
                    <p>{auth_stats['unique_ips']}</p>
                </div>
            </div>
            
            <h3>Top Usernames</h3>
            <table>
                <tr>
                    <th>Username</th>
                    <th>Count</th>
                </tr>
        """
        
        # Add top usernames
        for username, count in auth_stats['top_usernames'].items():
            html_report += f"""
                <tr>
                    <td>{username}</td>
                    <td>{count}</td>
                </tr>
            """
        
        html_report += """
            </table>
            
            <h3>Top Passwords</h3>
            <table>
                <tr>
                    <th>Password</th>
                    <th>Count</th>
                </tr>
        """
        
        # Add top passwords
        for password, count in auth_stats['top_passwords'].items():
            html_report += f"""
                <tr>
                    <td>{password}</td>
                    <td>{count}</td>
                </tr>
            """
        
        html_report += """
            </table>
            
            <h2>Command Analysis</h2>
            <div class="stats-container">
                <div class="stat-box">
                    <h3>Total Commands</h3>
                    <p>{}</p>
                </div>
                <div class="stat-box">
                    <h3>Unique IPs</h3>
                    <p>{}</p>
                </div>
            </div>
        """.format(command_stats['total_commands'], command_stats['unique_ips'])
        
        html_report += """
            <h3>Top Commands</h3>
            <table>
                <tr>
                    <th>Command</th>
                    <th>Count</th>
                </tr>
        """
        
        # Add top commands
        for command, count in command_stats['top_commands'].items():
            html_report += f"""
                <tr>
                    <td>{command}</td>
                    <td>{count}</td>
                </tr>
            """
        
        html_report += """
            </table>
            
            <h2>Visualizations</h2>
            <div id="map"></div>
            <div id="timeseries"></div>
            <div id="commandpie"></div>
            
            <script>
                // Placeholder for visualizations
                // These will be generated separately and included
            </script>
        </body>
        </html>
        """
        
        # Save HTML report
        report_file = os.path.join(output_dir, f'honeypot_report_{timestamp}.html')
        with open(report_file, 'w') as f:
            f.write(html_report)
        
        # Generate and save visualizations
        try:
            ip_map = self.generate_ip_map()
            if ip_map:
                ip_map.write_html(os.path.join(output_dir, f'ip_map_{timestamp}.html'))
                
            time_series = self.generate_time_series()
            if time_series:
                time_series.write_html(os.path.join(output_dir, f'time_series_{timestamp}.html'))
                
            command_pie = self.generate_command_pie()
            if command_pie:
                command_pie.write_html(os.path.join(output_dir, f'command_pie_{timestamp}.html'))
        except Exception as e:
            print(f"Error generating visualizations: {e}")
        
        return report_file

def main():
    """Main function to run the log analyzer"""
    analyzer = HoneypotLogAnalyzer()
    report_file = analyzer.generate_report()
    print(f"Report generated: {report_file}")

if __name__ == "__main__":
    main()