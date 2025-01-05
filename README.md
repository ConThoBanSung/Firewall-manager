# Firewall Manager

## Description
"Firewall Manager" is a simple GUI tool built using Python and PyQt5 that helps users manage and monitor the firewall status on Windows, macOS, and Linux operating systems. The application allows enabling/disabling the firewall, monitoring system logs, blocking IPs, and adding/removing firewall rules.

## Key Features
- **Firewall Management**: Enable/disable the firewall on the system.
- **IP Blocking**: Automatically block suspicious IP addresses based on system logs.
- **Log Monitoring**: Display system logs and automatically block IPs when necessary.
- **Add and Remove Rules**: Allow users to add or remove firewall rules based on port and action (ACCEPT/DROP).
- **Configuration Guide**: Download a firewall configuration guide.

## Main Components
- **Ensure Admin**: Ensures the application has administrator privileges when run.
- **Check Internet Access**: Ensures that the computer has an internet connection.
- **Check Firewall Status**: Checks the firewall status and displays it to the user.
- **Log Monitoring Thread**: Continuously monitors and displays system logs.
- **User Interface**: Provides a control panel for firewall management and log monitoring.

## Requirements
- Python 3.x
- PyQt5
- Administrator (root) privileges on the system
- Necessary firewall management commands for each OS (Windows: netsh, Linux: iptables, macOS: pfctl)

## Key Functions
- `ensure_admin()`: Checks and requests administrator privileges if not already present.
- `check_internet_access()`: Checks if there is an internet connection.
- `block_ip(ip)`: Blocks a specific IP address on the system.
- `check_firewall_status()`: Checks the firewall status on the system.
- `enable_firewall()` and `disable_firewall()`: Enables or disables the firewall.
- `LogMonitorThread`: Monitors system logs and automatically blocks suspicious IPs.

## Installation
1. Install PyQt5:
   ```bash
   pip install PyQt5
2. Run the application with administrator privileges.


## Usage
- Enable/Disable Firewall: Use the buttons on the interface to enable or disable the firewall.
- Monitor Logs: Click "Start Monitoring Logs" to view system logs.
- Add/Remove Rules: Enter rule information (port and action) and click the corresponding buttons to add or remove firewall rules.
- Download Guide: Click "Download Firewall Configuration Guide" to download a guide file.

## Example Interface

The application provides an intuitive interface with control panels for easily managing the firewall and monitoring system events.

## Notes
- The application requires administrator privileges to make changes to the firewall.
- 
- Features such as blocking IPs and monitoring logs require access to sensitive system files.
