# Network Topology Documentation

## Overview
The cyber range uses a segmented network topology to isolate vulnerable systems and provide realistic attack scenarios while maintaining security.

## Network Segments

### Management Network (192.168.0.0/24)
- **Purpose**: Administrative access and monitoring
- **Access**: Admin users only
- **Services**: Web interface, monitoring dashboard, VM management

### Lab Network (192.168.1.0/24)
- **Purpose**: Isolated environment for security testing
- **Access**: Students and attackers
- **Isolation**: No internet access, isolated from management network

## IP Address Allocation

| Host | IP Address | Purpose | Services |
|------|------------|---------|----------|
| Management Server | 192.168.0.10 | Web interface, monitoring | HTTP, SSH |
| Vulnerable Web | 192.168.1.10 | Web application testing | HTTP, FTP, Telnet |
| Target Server | 192.168.1.20 | Network reconnaissance | SSH, HTTP, SMB |
| Linux Target | 192.168.1.30 | Privilege escalation | SSH, Various |
| Kali Attacker | 192.168.1.100 | Attack platform | All tools |

## Network Rules

### Firewall Configuration
```
# Allow management network to access all systems
iptables -A FORWARD -s 192.168.0.0/24 -j ACCEPT

# Isolate lab network from internet
iptables -A FORWARD -s 192.168.1.0/24 -d 0.0.0.0/0 -j DROP

# Allow lab network internal communication
iptables -A FORWARD -s 192.168.1.0/24 -d 192.168.1.0/24 -j ACCEPT

# Block lab network access to management
iptables -A FORWARD -s 192.168.1.0/24 -d 192.168.0.0/24 -j DROP
```

### VirtualBox Network Configuration
```bash
# Create host-only networks
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.0.1 --netmask 255.255.255.0
VBoxManage hostonlyif ipconfig vboxnet1 --ip 192.168.1.1 --netmask 255.255.255.0

# Configure DHCP (optional)
VBoxManage dhcpserver add --netname HostInterfaceNetworking-vboxnet1 --ip 192.168.1.1 --netmask 255.255.255.0 --lowerip 192.168.1.100 --upperip 192.168.1.200
```

## Security Considerations

### Network Isolation
- Lab network has no internet access
- Management network is separated from lab network
- Each VM can only communicate within its designated segment

### Monitoring Points
- All traffic between segments is logged
- Network intrusion detection on management network
- Traffic analysis for educational purposes

### Access Control
- Students can only access lab network
- Administrators have access to both networks
- VM console access through management interface only

## Implementation Steps

1. **Physical/Virtual Infrastructure**
   - Set up hypervisor (VirtualBox/VMware)
   - Create virtual networks
   - Configure network isolation

2. **VM Deployment**
   - Deploy VMs using Vagrant files
   - Configure network interfaces
   - Test connectivity

3. **Security Configuration**
   - Implement firewall rules
   - Configure monitoring
   - Test isolation

4. **Validation**
   - Verify network segmentation
   - Test attack scenarios
   - Confirm monitoring functionality
