```markdown
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
- Successful SSH login monitoring
- Invalid username identification
- SSH event normalization
- Per-source-IP failed-attempt tracking
- Configurable brute-force threshold
- Configurable sliding time window
- Duplicate incident suppression
- Dry-run response mode
- Real automated firewall response
- Temporary nftables IP blocking
- Automatic firewall block expiration
- Tailscale management-path protection
- Synthetic detector testing
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
```

## How Detection Works

SSHGuard tracks failed SSH authentication attempts independently for each source IP address.

The detector uses two main values:

- **Threshold**: The number of failed authentication attempts required to trigger detection.
- **Time Window**: The period of time during which those attempts must occur.

For example:

```text
Threshold: 3 attempts
Time Window: 20 seconds
```

If the same source IP generates three failed SSH authentication attempts within 20 seconds, SSHGuard creates a brute-force incident.

SSHGuard uses a sliding time window. Old authentication attempts that fall outside the active time window are automatically removed from the current calculation.

Example:

```text
10:00:00 Failed
10:00:05 Failed
10:00:12 Failed
```

If the configured threshold is 3 attempts within 20 seconds:

```text
3 failed attempts
within 20 seconds
=
Brute-force detected
```

## SSH Event Processing

Raw OpenSSH authentication messages are read from the systemd journal.

Example raw event:

```text
Failed password for user from 192.168.0.11 port 50500 ssh2
```

The parser converts this raw message into a normalized event containing information such as:

```text
event_type
username
source_ip
source_port
timestamp
invalid_user
```

This separation allows the Detection Engine to work with structured security events instead of parsing raw log messages directly.

## Events Currently Monitored

SSHGuard currently recognizes:

- Failed password authentication
- Successful password authentication
- Invalid username attempts

Failed authentication events are passed to the brute-force detector.

Successful login events are monitored and displayed but are not counted toward the brute-force detection threshold.

## Automated Firewall Response

SSHGuard supports two response modes.

### Dry-Run Mode

The system detects brute-force activity and reports the action that would have been performed, but it does not modify the firewall.

Example:

```text
[DRY RUN] Would block IP: 192.168.0.11 for 60 seconds
```

### Real Mode

When real response mode is enabled, SSHGuard creates and manages its own nftables firewall table.

A detected source IPv4 address is inserted into a temporary nftables set.

SSH traffic from that source to the protected SSH port is dropped.

Example:

```text
[FIREWALL] BLOCKED 192.168.0.11 for 60 seconds
```

The block automatically expires after the configured timeout.

This means the Python application does not need to manually sleep and later remove the firewall rule.

The Linux kernel and nftables handle the expiration automatically.

## Firewall Safety

SSHGuard uses its own nftables table:

```text
inet sshguard
```

The project does not flush or replace existing firewall configurations.

This helps avoid interfering with:

- UFW
- Docker networking
- Tailscale
- Other existing firewall rules

The current firewall architecture also excludes traffic arriving through the Tailscale interface from SSHGuard blocking.

Tailscale is currently used as an administrative and recovery path.

## Real Test Scenario

The system has been tested using the following configuration:

```text
Threshold: 3 failed attempts
Time Window: 20 seconds
Block Duration: 60 seconds
Protected SSH Port: 22
```

During testing:

1. A client generated three failed SSH authentication attempts.
2. SSHGuard detected that the configured threshold had been reached.
3. A brute-force security incident was created.
4. The attacking source IP was added to the nftables temporary block set.
5. New SSH connections from the blocked client timed out.
6. The source IP remained blocked for the configured duration.
7. nftables automatically removed the IP after the timeout.
8. SSH connectivity became available again after the block expired.

Example detection output:

```text
[FAILED LOGIN] IP=192.168.0.11 USER=mc
[DETECTOR] IP=192.168.0.11 ATTEMPTS=1/3

[FAILED LOGIN] IP=192.168.0.11 USER=mc
[DETECTOR] IP=192.168.0.11 ATTEMPTS=2/3

[FAILED LOGIN] IP=192.168.0.11 USER=mc
[DETECTOR] IP=192.168.0.11 ATTEMPTS=3/3

[!!!] BRUTE FORCE DETECTED

Source IP: 192.168.0.11
Attempts: 3

[FIREWALL] BLOCKED 192.168.0.11 for 60 seconds
```

While the block was active:

```text
ssh: connect to host 192.168.0.8 port 22: Connection timed out
```

After the firewall timeout expired, SSH access became available again.

## Project Structure

```text
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
```

## Main Components

### `main.py`

Main application entry point.

Responsibilities:

- Initializes the detector
- Initializes the firewall manager
- Starts SSH event monitoring
- Displays normalized events
- Sends events to the Detection Engine
- Processes detected security incidents
- Triggers the configured response

### `config.py`

Stores configurable project settings.

Current configuration includes:

- Brute-force threshold
- Sliding time-window duration
- Firewall block duration
- Protected SSH port
- Response mode
- Whitelisted management networks

### `core/log_parser.py`

Responsible for:

- Reading OpenSSH events from systemd journal
- Parsing SSH authentication messages
- Extracting relevant information
- Converting raw logs into normalized events

### `core/detector.py`

Responsible for:

- Tracking failed login attempts per source IP
- Maintaining sliding time-window state
- Removing expired attempts
- Comparing attempt counts against the configured threshold
- Generating brute-force incidents
- Suppressing repeated incidents during the same continuous attack

### `core/firewall.py`

Responsible for:

- Managing SSHGuard's nftables configuration
- Protecting configured management paths
- Blocking malicious source IP addresses
- Using temporary nftables timeout sets
- Supporting Dry-Run and Real response modes
- Supporting manual unblock operations

### `tests/test_detector.py`

Contains synthetic tests for the Detection Engine.

These tests allow the detector logic to be validated independently from:

- OpenSSH
- systemd journal
- Network traffic
- Firewall rules

## Requirements

Current development environment:

- Raspberry Pi 4
- Debian GNU/Linux 13
- Python 3.13+
- OpenSSH Server
- systemd
- nftables
- Git

Real firewall response requires elevated privileges.

No third-party Python packages are currently required by the core SSHGuard implementation.

## Running SSHGuard

Clone or enter the project directory:

```bash
cd sshguard
```

Run the application:

```bash
sudo python3 main.py
```

When SSHGuard starts, it displays the current configuration.

Example:

```text
======================================
 SSHGuard
 Brute-Force Detection
 & Automatic Blocking System
======================================

Threshold:       3
Time Window:     20s
Block Duration:  60s
SSH Port:        22
Response Mode:   REAL
```

## Configuration

Edit:

```text
config.py
```

Example configuration:

```python
THRESHOLD = 3
WINDOW_SECONDS = 20

BLOCK_DURATION_SECONDS = 60

PROTECTED_SSH_PORT = 22

RESPONSE_MODE = "dry-run"

WHITELIST_NETWORKS = [
    "100.64.0.0/10",
    "127.0.0.0/8",
]
```

### Response Modes

Safe testing:

```python
RESPONSE_MODE = "dry-run"
```

Real firewall enforcement:

```python
RESPONSE_MODE = "real"
```

Always verify network access and recovery paths before enabling real firewall enforcement.

## Detector Testing

Run the detector tests from the project root:

```bash
python3 -m tests.test_detector
```

The synthetic detector tests verify behavior such as:

- Per-IP attempt tracking
- Sliding time-window logic
- Threshold detection
- Multiple independent source IP addresses
- Successful login events not increasing the failure counter

## Inspecting SSHGuard Firewall State

Display the SSHGuard nftables table:

```bash
sudo nft list table inet sshguard
```

Display currently blocked IPv4 addresses:

```bash
sudo nft list set inet sshguard blocked_ipv4
```

Example active block:

```text
elements = {
    192.168.0.11 expires 24s
}
```

When the timeout expires, the source IP is automatically removed.

## Removing the SSHGuard Firewall Table

If the SSHGuard firewall table needs to be removed manually:

```bash
sudo nft delete table inet sshguard
```

This removes only the firewall table created by SSHGuard.

It does not flush the entire system firewall.

## Security Considerations

This project is intended for defensive cybersecurity purposes only.

All testing must be performed on systems owned by the project team or systems for which explicit authorization has been provided.

The repository must never contain:

- Real passwords
- SSH private keys
- API credentials
- Tokens
- Sensitive authentication data
- Private environment files
- Real captured credentials

The project does not store SSH passwords.

## Current Development Status

### Completed

- Real-time OpenSSH journal monitoring
- Failed-login parsing
- Successful-login parsing
- Invalid-user detection
- Event normalization
- Per-source-IP tracking
- Sliding time-window detection
- Configurable threshold
- Configurable block duration
- Brute-force incident generation
- Duplicate incident suppression
- Synthetic Detection Engine testing
- Real SSH end-to-end testing
- Dry-Run response mode
- Real nftables response mode
- Temporary automatic firewall blocking
- Automatic block expiration
- Protected Tailscale management path
- Git repository initialization

### In Progress

- Expanded automated testing
- Persistent security-event storage
- SQLite integration
- Monitoring dashboard
- systemd service deployment
- Additional documentation
- Final demonstration environment

### Planned Improvements

Possible future improvements include:

- Security event database
- Monitoring dashboard
- Active block management
- Incident history
- Additional SSH event analysis
- Multiple protected services
- Alert notifications
- Extended reporting
- Deployment as a persistent Linux service

## Educational Purpose

SSHGuard is being developed as a cybersecurity graduation project.

The purpose of the project is not only to produce a working security tool, but also to demonstrate understanding of:

- Linux authentication logging
- OpenSSH
- Log parsing
- Event normalization
- Python
- Stateful security detection
- Sliding time windows
- Brute-force detection
- Automated defensive response
- Linux firewall management
- nftables
- Testing and validation

## Disclaimer

SSHGuard is an educational defensive-security project.

Use it only on systems you own or are explicitly authorized to test.
