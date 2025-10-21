# HoneyNet: Advanced Honeypot System

## Project Overview
HoneyNet is a sophisticated honeypot system designed to detect, analyze, and visualize cyber attack patterns in real-time. By emulating vulnerable services, it attracts attackers and provides valuable insights into their tactics, techniques, and procedures.

## Key Features

### 1. SSH Service Emulation
- Simulates a vulnerable SSH server
- Captures login attempts with usernames and passwords
- Records all commands executed by attackers
- Provides realistic responses to maintain attacker engagement

### 2. Comprehensive Logging
- Detailed logs of all connection attempts
- Authentication attempt tracking
- Command execution history
- Structured data for easy analysis

### 3. Geolocation Tracking
- Maps attack origins in real-time
- Country-based attack statistics
- Visual representation of global attack patterns

### 4. Real-time Visualization Dashboard
- Interactive attack map
- Timeline of attack attempts
- Top usernames and passwords used
- Recent attack details table
- Auto-refreshing data

### 5. Automated Defense with Fail2ban Integration
- Automatic blocking of persistent attackers
- Configurable threshold settings
- IP ban management
- Cross-platform support (Windows/Linux)

## Technical Architecture

```
HoneyNet
├── honeypot_server.py    # Core SSH honeypot implementation
├── log_analyzer.py       # Log processing and analysis
├── dashboard.py          # Web visualization interface
├── update_geoip.py       # GeoIP database management
├── fail2ban_integration.py # Automated IP blocking
├── start_honeypot.py     # Unified startup script
└── config.json           # System configuration
```

## Implementation Details

### Honeypot Server
- Built with Python using Paramiko and Twisted
- Configurable SSH banner and port
- Simulated filesystem and shell environment
- Detailed logging of all interactions

### Dashboard
- Flask-based web interface
- Interactive visualizations with Plotly
- Real-time data updates
- Responsive design for all devices

### Security Features
- IP-based rate limiting
- Automatic blocking of aggressive scanners
- Safe execution environment for attacker commands

## Demo Insights

Based on our sample data collection:

- Most common usernames: root, admin, user
- Most common passwords: 123456, password, admin
- Top attack origins: China, Russia, United States
- Common attack patterns: credential stuffing, known exploit attempts

## Future Enhancements

- Additional service emulation (FTP, Telnet, Web)
- Machine learning for attack pattern recognition
- Threat intelligence integration
- Distributed honeypot network
- Advanced attacker profiling

## Conclusion

HoneyNet provides security researchers and organizations with:
- Valuable insights into current attack methodologies
- Early warning system for new attack vectors
- Training data for security teams
- Enhanced understanding of the threat landscape

## How to Run

```bash
# Start all components
python start_honeypot.py

# Start individual components
python start_honeypot.py --honeypot-only
python start_honeypot.py --dashboard-only
```

## Thank You!

Contact: [Your Contact Information]
GitHub: [Your GitHub Repository]