# SSHGuard

Real-Time SSH Brute-Force Detection & Automatic Blocking System

## Overview

SSHGuard is a defensive cybersecurity graduation project designed to detect repeated failed SSH authentication attempts and automatically apply temporary firewall blocks against suspicious source IP addresses.

The system monitors OpenSSH authentication events in real time through the systemd journal, normalizes relevant events, tracks failed login attempts separately for each source IP, evaluates them using a configurable sliding time window and threshold, and triggers an automated nftables response when brute-force behavior is detected.

The project is currently deployed and tested on a Raspberry Pi 4 running Debian 13.

## Team

- Mohammed Jumaa Al-Tahla
- Nada
- Doha

## Current Features

- Real-time OpenSSH event monitoring
- systemd journal integration
- Failed SSH login detection
- Successful login monitoring
- Invalid username identification
- SSH event normalization
- Per-source-IP attempt tracking
- Configurable brute-force threshold
- Configurable sliding time window
- Duplicate incident suppression
- Dry-run response mode
- Real automated firewall response
- Temporary nftables IP blocking
- Automatic firewall block expiration
- Tailscale management-path protection
- Synthetic detector tests
- Real end-to-end SSH testing

## Architecture

```text
SSH Client
    |
    v
OpenSSH Server
    |
    v
systemd journal
    |
    v
SSH Event Parser
    |
    v
Normalized Events
    |
    v
Brute-Force Detector
    |
    v
Security Incident
    |
    v
Firewall Manager
    |
    v
nftables Temporary Block
Detection Logic
SSHGuard tracks failed authentication events independently for each source IP.
A brute-force incident is generated when:
failed attempts >= configured threshold
within the configured sliding time window.
Example:
Threshold: 3 attempts
Time Window: 20 seconds
If the same source IP generates three failed SSH authentication attempts within 20 seconds, SSHGuard creates a brute-force incident.
Old authentication attempts that fall outside the active sliding time window are automatically removed from the current calculation.
Automated Response
When a new brute-force incident is detected, SSHGuard can operate in one of two modes.
Dry-Run Mode
The system detects and reports the attack but does not modify the firewall.
Real Mode
The source IPv4 address is inserted into a dedicated nftables timeout set.
Only SSH traffic from the blocked IP to the configured protected SSH port is dropped.
The block automatically expires after the configured duration.
SSHGuard uses its own nftables table and does not flush or replace the existing UFW, Docker, or Tailscale firewall configuration.
Tested Scenario
The current test configuration uses:
Threshold: 3 failed attempts
Time Window: 20 seconds
Block Duration: 60 seconds
Protected SSH Port: 22
During real testing:
1. A client generated three failed SSH authentication attempts.
2. SSHGuard detected the brute-force condition.
3. The source IP was added to the nftables temporary block set.
4. New SSH connections from that source timed out.
5. The block remained active for the configured duration.
6. nftables automatically removed the source IP after the timeout.
7. SSH connectivity became available again.
Project Structure
sshguard/
├── main.py
├── config.py
├── core/
│   ├── __init__.py
│   ├── log_parser.py
│   ├── detector.py
│   └── firewall.py
├── tests/
│   ├── __init__.py
│   └── test_detector.py
├── .gitignore
└── README.md
Requirements
Current development environment:
- Debian 13
- Python 3.13+
- OpenSSH Server
- systemd
- nftables
- root privileges for real firewall response
No third-party Python packages are currently required for the core system.
Running the Project
From the project directory:
sudo python3 main.py
The system requires elevated privileges when real firewall response is enabled because nftables rules must be modified.
Configuration
Core configuration is stored in:
config.py
Current configurable settings include:
- Detection threshold
- Sliding time-window duration
- Firewall block duration
- Protected SSH port
- Response mode
- Whitelisted management networks
Testing
Run the detector test module from the project root:
python3 -m tests.test_detector
Testing is performed only against systems owned and controlled by the project team.
Safety
This project is intended strictly for defensive cybersecurity use.
Do not use it to test or attack third-party systems without explicit authorization.
The project does not store SSH passwords or authentication credentials.
Sensitive credentials, private keys, environment files, database files, and logs must not be committed to the repository.
Current Development Status
Completed:
- Real-time SSH event monitoring
- Event parsing and normalization
- Sliding-window brute-force detection
- Per-IP state tracking
- Duplicate incident suppression
- Dry-run response
- Real nftables blocking
- Automatic block expiration
- Real end-to-end testing
In Progress:
- Persistent event storage
- SQLite integration
- Monitoring dashboard
- Additional automated tests
- Deployment as a systemd service
- Extended documentation
- Final demonstration environment
Disclaimer
SSHGuard is an educational defensive-security project developed for a cybersecurity graduation project. It must only be deployed and tested in authorized environments.
