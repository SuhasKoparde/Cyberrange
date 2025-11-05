# Custom Cyber Range - Final Year Project

## Overview
A comprehensive cyber range environment for cybersecurity training and assessment. This project provides isolated virtual environments with vulnerable systems, attack scenarios, and monitoring capabilities.

## Features
- **Vulnerable VMs**: Pre-configured vulnerable machines for penetration testing
- **Network Isolation**: Segmented networks to prevent lateral movement
- **Attack Scenarios**: Guided challenges and CTF-style exercises
- **Monitoring Dashboard**: Real-time monitoring and logging
- **Web Interface**: User-friendly challenge management system

## Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Admin Panel   │    │  Monitoring     │    │   User Portal   │
│   (Web UI)      │    │   Dashboard     │    │   (Challenges)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │              Management Network               │
         └───────────────────────┼───────────────────────┘
                                 │
    ┌────────────────────────────┼────────────────────────────┐
    │                    Isolated Lab Network                 │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
    │  │ Vulnerable  │  │ Vulnerable  │  │   Attack    │    │
    │  │   Linux     │  │  Windows    │  │   Machine   │    │
    │  │    VM       │  │     VM      │  │   (Kali)    │    │
    │  └─────────────┘  └─────────────┘  └─────────────┘    │
    └────────────────────────────────────────────────────────┘
```

## Technology Stack
- **Virtualization**: VirtualBox/VMware
- **Backend**: Python Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **Database**: SQLite
- **Monitoring**: ELK Stack (Elasticsearch, Logstash, Kibana)
- **Networking**: Virtual networks with pfSense firewall

## Getting Started
1. Install dependencies: `pip install -r requirements.txt`
2. Set up virtual machines using provided configurations
3. Configure network topology
4. Start the web interface: `python app.py`
5. Access the dashboard at `http://localhost:5000`

## Project Structure
```
CyberRange/
├── app/                    # Web application
├── vms/                    # VM configurations
├── network/                # Network topology files
├── challenges/             # Attack scenarios
├── monitoring/             # Logging and monitoring
├── docs/                   # Documentation
└── scripts/                # Automation scripts
```

## Academic Objectives
- Demonstrate understanding of cybersecurity principles
- Implement network security and isolation
- Create realistic attack scenarios
- Develop monitoring and incident response capabilities
- Build user-friendly interfaces for security training

## License
MIT License - Educational Use
