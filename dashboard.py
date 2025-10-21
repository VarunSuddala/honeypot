#!/usr/bin/env python3
"""
Honeypot Dashboard
Web interface for visualizing honeypot attack data
"""

import os
import json
import datetime
from flask import Flask, render_template, jsonify, request
import pandas as pd
import plotly
import plotly.express as px
import plotly.graph_objects as go
from log_analyzer import HoneypotLogAnalyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Create templates directory if it doesn't exist
if not os.path.exists('templates'):
    os.makedirs('templates')

# Create static directory if it doesn't exist
if not os.path.exists('static'):
    os.makedirs('static')

# Create HTML template
with open('templates/index.html', 'w') as f:
    f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>Honeypot Attack Dashboard</h1>
            <p>Real-time monitoring of attack patterns</p>
        </header>
        
        <div class="stats-row">
            <div class="stat-box">
                <h3>Total Attacks</h3>
                <div class="stat-value" id="total-attacks">0</div>
            </div>
            <div class="stat-box">
                <h3>Unique IPs</h3>
                <div class="stat-value" id="unique-ips">0</div>
            </div>
            <div class="stat-box">
                <h3>Countries</h3>
                <div class="stat-value" id="countries">0</div>
            </div>
            <div class="stat-box">
                <h3>Last Attack</h3>
                <div class="stat-value" id="last-attack">Never</div>
            </div>
        </div>
        
        <div class="row">
            <div class="chart-container">
                <h2>Attack Origins</h2>
                <div id="map-chart"></div>
            </div>
        </div>
        
        <div class="row">
            <div class="chart-container half">
                <h2>Attacks Over Time</h2>
                <div id="time-chart"></div>
            </div>
            <div class="chart-container half">
                <h2>Command Categories</h2>
                <div id="command-chart"></div>
            </div>
        </div>
        
        <div class="row">
            <div class="table-container half">
                <h2>Top Usernames</h2>
                <table id="username-table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Will be populated by JavaScript -->
                    </tbody>
                </table>
            </div>
            <div class="table-container half">
                <h2>Top Passwords</h2>
                <table id="password-table">
                    <thead>
                        <tr>
                            <th>Password</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Will be populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="row">
            <div class="table-container">
                <h2>Recent Attack Attempts</h2>
                <table id="attacks-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP</th>
                            <th>Country</th>
                            <th>Username</th>
                            <th>Password</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Will be populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <footer>
        <p>Honeypot Dashboard | Last updated: <span id="last-updated">Never</span></p>
    </footer>
    
    <script>
        // Function to update the dashboard
        function updateDashboard() {
            $.getJSON('/api/dashboard-data', function(data) {
                // Update stats
                $('#total-attacks').text(data.auth_stats.total_attempts);
                $('#unique-ips').text(data.auth_stats.unique_ips);
                $('#countries').text(data.country_count);
                $('#last-attack').text(data.last_attack);
                $('#last-updated').text(new Date().toLocaleString());
                
                // Update charts
                Plotly.newPlot('map-chart', data.map_data.data, data.map_data.layout);
                Plotly.newPlot('time-chart', data.time_data.data, data.time_data.layout);
                Plotly.newPlot('command-chart', data.command_data.data, data.command_data.layout);
                
                // Update username table
                var usernameTable = $('#username-table tbody');
                usernameTable.empty();
                $.each(data.auth_stats.top_usernames, function(username, count) {
                    usernameTable.append('<tr><td>' + username + '</td><td>' + count + '</td></tr>');
                });
                
                // Update password table
                var passwordTable = $('#password-table tbody');
                passwordTable.empty();
                $.each(data.auth_stats.top_passwords, function(password, count) {
                    passwordTable.append('<tr><td>' + password + '</td><td>' + count + '</td></tr>');
                });
                
                // Update attacks table
                var attacksTable = $('#attacks-table tbody');
                attacksTable.empty();
                $.each(data.recent_attacks, function(i, attack) {
                    attacksTable.append(
                        '<tr><td>' + attack.time + '</td><td>' + attack.ip + '</td><td>' + 
                        attack.country + '</td><td>' + attack.username + '</td><td>' + 
                        attack.password + '</td></tr>'
                    );
                });
            });
        }
        
        // Update dashboard on load and every 30 seconds
        $(document).ready(function() {
            updateDashboard();
            setInterval(updateDashboard, 30000);
        });
    </script>
</body>
</html>
    """)

# Create CSS file
with open('static/style.css', 'w') as f:
    f.write("""
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

body {
    background-color: #f5f5f5;
    color: #333;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

header {
    text-align: center;
    margin-bottom: 30px;
    padding: 20px;
    background-color: #2c3e50;
    color: white;
    border-radius: 5px;
}

header h1 {
    margin-bottom: 10px;
}

.stats-row {
    display: flex;
    justify-content: space-between;
    margin-bottom: 20px;
}

.stat-box {
    flex: 1;
    background-color: white;
    padding: 15px;
    margin: 0 10px;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    text-align: center;
}

.stat-box:first-child {
    margin-left: 0;
}

.stat-box:last-child {
    margin-right: 0;
}

.stat-value {
    font-size: 24px;
    font-weight: bold;
    margin-top: 10px;
    color: #2980b9;
}

.row {
    display: flex;
    margin-bottom: 20px;
}

.chart-container, .table-container {
    background-color: white;
    padding: 20px;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    width: 100%;
}

.half {
    width: calc(50% - 10px);
}

.chart-container.half:first-child, .table-container.half:first-child {
    margin-right: 20px;
}

h2 {
    margin-bottom: 15px;
    color: #2c3e50;
}

table {
    width: 100%;
    border-collapse: collapse;
}

table th, table td {
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid #ddd;
}

table th {
    background-color: #f2f2f2;
    font-weight: bold;
}

table tr:hover {
    background-color: #f9f9f9;
}

footer {
    text-align: center;
    padding: 20px;
    color: #7f8c8d;
    font-size: 14px;
}

#map-chart, #time-chart, #command-chart {
    height: 400px;
}

@media (max-width: 768px) {
    .stats-row, .row {
        flex-direction: column;
    }
    
    .stat-box {
        margin: 0 0 10px 0;
    }
    
    .half {
        width: 100%;
        margin-right: 0 !important;
        margin-bottom: 20px;
    }
}
    """)

@app.route('/')
def index():
    """Render the dashboard homepage"""
    return render_template('index.html')

@app.route('/api/dashboard-data')
def dashboard_data():
    """API endpoint to get dashboard data"""
    analyzer = HoneypotLogAnalyzer()
    
    # Get authentication statistics
    auth_stats = analyzer.analyze_auth_attempts()
    
    # Get command statistics
    command_stats = analyzer.analyze_commands()
    
    # Get recent attacks
    recent_attacks = []
    attempts = analyzer.load_auth_attempts()
    if attempts:
        # Sort by timestamp (newest first)
        attempts.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Get unique IPs
        ips = list(set(a['ip'] for a in attempts))
        
        # Get geolocation data
        locations = analyzer.get_ip_locations(ips)
        
        # Format recent attacks
        for attempt in attempts[:10]:  # Show only the 10 most recent
            ip = attempt['ip']
            country = locations.get(ip, {}).get('country', 'Unknown')
            
            recent_attacks.append({
                'time': attempt['timestamp'],
                'ip': ip,
                'country': country,
                'username': attempt['username'],
                'password': attempt['password']
            })
    
    # Generate map data
    map_fig = analyzer.generate_ip_map()
    map_data = {'data': [], 'layout': {}}
    if map_fig:
        map_data = json.loads(map_fig.to_json())
    
    # Generate time series data
    time_fig = analyzer.generate_time_series()
    time_data = {'data': [], 'layout': {}}
    if time_fig:
        time_data = json.loads(time_fig.to_json())
    
    # Generate command category data
    command_fig = analyzer.generate_command_pie()
    command_data = {'data': [], 'layout': {}}
    if command_fig:
        command_data = json.loads(command_fig.to_json())
    
    # Count unique countries
    country_count = 0
    if attempts:
        countries = set()
        for ip in ips:
            if ip in locations:
                countries.add(locations[ip]['country'])
        country_count = len(countries)
    
    # Get timestamp of last attack
    last_attack = "Never"
    if attempts:
        last_attack = attempts[0]['timestamp']
    
    return jsonify({
        'auth_stats': auth_stats,
        'command_stats': command_stats,
        'recent_attacks': recent_attacks,
        'map_data': map_data,
        'time_data': time_data,
        'command_data': command_data,
        'country_count': country_count,
        'last_attack': last_attack
    })

def main():
    """Main function to run the dashboard"""
    print("Starting Honeypot Dashboard...")
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == "__main__":
    main()