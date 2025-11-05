#!/usr/bin/env python3
"""
Virtual Machine Management Script for Cyber Range
Automates VM deployment, configuration, and management
"""

import os
import sys
import json
import subprocess
import time
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class VMManager:
    """Manages virtual machines for the cyber range"""
    
    def __init__(self, config_path='vm_config.json'):
        self.config_path = config_path
        self.vms = self.load_config()
        self.base_path = Path(__file__).parent.parent
    
    def load_config(self):
        """Load VM configuration from JSON file"""
        config_file = Path(self.config_path)
        if config_file.exists():
            with open(config_file, 'r') as f:
                return json.load(f)
        else:
            return self.create_default_config()
    
    def create_default_config(self):
        """Create default VM configuration"""
        default_config = {
            "vms": {
                "vulnerable-web": {
                    "name": "CyberRange-VulnerableWeb",
                    "box": "ubuntu/focal64",
                    "ip": "192.168.1.10",
                    "memory": 1024,
                    "cpus": 2,
                    "path": "vms/vulnerable-web",
                    "services": ["apache2", "mysql", "vsftpd"]
                },
                "linux-target": {
                    "name": "CyberRange-LinuxTarget",
                    "box": "ubuntu/focal64",
                    "ip": "192.168.1.30",
                    "memory": 1024,
                    "cpus": 2,
                    "path": "vms/linux-target",
                    "services": ["ssh", "cron"]
                },
                "kali-attacker": {
                    "name": "CyberRange-KaliAttacker",
                    "box": "kalilinux/rolling",
                    "ip": "192.168.1.100",
                    "memory": 2048,
                    "cpus": 2,
                    "path": "vms/kali-attacker",
                    "services": ["ssh", "postgresql"]
                }
            }
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        return default_config
    
    def run_command(self, command, cwd=None):
        """Execute shell command and return result"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=300
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command}")
            return False, "", "Command timed out"
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return False, "", str(e)
    
    def check_prerequisites(self):
        """Check if required tools are installed"""
        tools = ['vagrant', 'VBoxManage']
        missing_tools = []
        
        for tool in tools:
            success, _, _ = self.run_command(f"which {tool}")
            if not success:
                missing_tools.append(tool)
        
        if missing_tools:
            logger.error(f"Missing required tools: {', '.join(missing_tools)}")
            return False
        
        logger.info("All prerequisites satisfied")
        return True
    
    def setup_network(self):
        """Setup VirtualBox host-only networks"""
        logger.info("Setting up virtual networks...")
        
        # Create host-only network for lab environment
        commands = [
            "VBoxManage hostonlyif create",
            "VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.1.1 --netmask 255.255.255.0"
        ]
        
        for cmd in commands:
            success, stdout, stderr = self.run_command(cmd)
            if not success and "already exists" not in stderr:
                logger.warning(f"Network setup warning: {stderr}")
        
        logger.info("Network setup completed")
    
    def deploy_vm(self, vm_name):
        """Deploy a specific VM"""
        if vm_name not in self.vms['vms']:
            logger.error(f"VM {vm_name} not found in configuration")
            return False
        
        vm_config = self.vms['vms'][vm_name]
        vm_path = self.base_path / vm_config['path']
        
        logger.info(f"Deploying VM: {vm_name}")
        
        # Check if Vagrantfile exists
        vagrantfile = vm_path / 'Vagrantfile'
        if not vagrantfile.exists():
            logger.error(f"Vagrantfile not found: {vagrantfile}")
            return False
        
        # Run vagrant up
        success, stdout, stderr = self.run_command("vagrant up", cwd=vm_path)
        
        if success:
            logger.info(f"VM {vm_name} deployed successfully")
            return True
        else:
            logger.error(f"Failed to deploy VM {vm_name}: {stderr}")
            return False
    
    def start_vm(self, vm_name):
        """Start a VM"""
        if vm_name not in self.vms['vms']:
            logger.error(f"VM {vm_name} not found")
            return False
        
        vm_config = self.vms['vms'][vm_name]
        vm_path = self.base_path / vm_config['path']
        
        logger.info(f"Starting VM: {vm_name}")
        success, stdout, stderr = self.run_command("vagrant up", cwd=vm_path)
        
        if success:
            logger.info(f"VM {vm_name} started successfully")
            return True
        else:
            logger.error(f"Failed to start VM {vm_name}: {stderr}")
            return False
    
    def stop_vm(self, vm_name):
        """Stop a VM"""
        if vm_name not in self.vms['vms']:
            logger.error(f"VM {vm_name} not found")
            return False
        
        vm_config = self.vms['vms'][vm_name]
        vm_path = self.base_path / vm_config['path']
        
        logger.info(f"Stopping VM: {vm_name}")
        success, stdout, stderr = self.run_command("vagrant halt", cwd=vm_path)
        
        if success:
            logger.info(f"VM {vm_name} stopped successfully")
            return True
        else:
            logger.error(f"Failed to stop VM {vm_name}: {stderr}")
            return False
    
    def restart_vm(self, vm_name):
        """Restart a VM"""
        logger.info(f"Restarting VM: {vm_name}")
        if self.stop_vm(vm_name):
            time.sleep(5)  # Wait a bit between stop and start
            return self.start_vm(vm_name)
        return False
    
    def get_vm_status(self, vm_name=None):
        """Get status of VMs"""
        if vm_name:
            vm_names = [vm_name]
        else:
            vm_names = list(self.vms['vms'].keys())
        
        status_info = {}
        
        for name in vm_names:
            if name not in self.vms['vms']:
                continue
            
            vm_config = self.vms['vms'][name]
            vm_path = self.base_path / vm_config['path']
            
            # Get vagrant status
            success, stdout, stderr = self.run_command("vagrant status", cwd=vm_path)
            
            if success:
                if "running" in stdout:
                    status = "running"
                elif "poweroff" in stdout:
                    status = "stopped"
                else:
                    status = "unknown"
            else:
                status = "error"
            
            status_info[name] = {
                'status': status,
                'ip': vm_config['ip'],
                'name': vm_config['name']
            }
        
        return status_info
    
    def deploy_all(self):
        """Deploy all VMs"""
        logger.info("Deploying all VMs...")
        
        if not self.check_prerequisites():
            return False
        
        self.setup_network()
        
        success_count = 0
        total_count = len(self.vms['vms'])
        
        for vm_name in self.vms['vms']:
            if self.deploy_vm(vm_name):
                success_count += 1
        
        logger.info(f"Deployment complete: {success_count}/{total_count} VMs deployed successfully")
        return success_count == total_count
    
    def start_all(self):
        """Start all VMs"""
        logger.info("Starting all VMs...")
        
        success_count = 0
        total_count = len(self.vms['vms'])
        
        for vm_name in self.vms['vms']:
            if self.start_vm(vm_name):
                success_count += 1
        
        logger.info(f"Start complete: {success_count}/{total_count} VMs started successfully")
        return success_count == total_count
    
    def stop_all(self):
        """Stop all VMs"""
        logger.info("Stopping all VMs...")
        
        success_count = 0
        total_count = len(self.vms['vms'])
        
        for vm_name in self.vms['vms']:
            if self.stop_vm(vm_name):
                success_count += 1
        
        logger.info(f"Stop complete: {success_count}/{total_count} VMs stopped successfully")
        return success_count == total_count
    
    def destroy_vm(self, vm_name):
        """Destroy a VM (removes it completely)"""
        if vm_name not in self.vms['vms']:
            logger.error(f"VM {vm_name} not found")
            return False
        
        vm_config = self.vms['vms'][vm_name]
        vm_path = self.base_path / vm_config['path']
        
        logger.warning(f"Destroying VM: {vm_name}")
        success, stdout, stderr = self.run_command("vagrant destroy -f", cwd=vm_path)
        
        if success:
            logger.info(f"VM {vm_name} destroyed successfully")
            return True
        else:
            logger.error(f"Failed to destroy VM {vm_name}: {stderr}")
            return False
    
    def reset_environment(self):
        """Reset the entire environment"""
        logger.warning("Resetting entire cyber range environment...")
        
        # Stop all VMs first
        self.stop_all()
        
        # Destroy all VMs
        for vm_name in self.vms['vms']:
            self.destroy_vm(vm_name)
        
        # Redeploy all VMs
        return self.deploy_all()

def main():
    """Main CLI interface"""
    if len(sys.argv) < 2:
        print("Usage: python vm_manager.py <command> [vm_name]")
        print("Commands:")
        print("  deploy [vm_name]  - Deploy VM(s)")
        print("  start [vm_name]   - Start VM(s)")
        print("  stop [vm_name]    - Stop VM(s)")
        print("  restart [vm_name] - Restart VM(s)")
        print("  status [vm_name]  - Get VM status")
        print("  destroy [vm_name] - Destroy VM(s)")
        print("  reset             - Reset entire environment")
        print("  check             - Check prerequisites")
        return
    
    manager = VMManager()
    command = sys.argv[1].lower()
    vm_name = sys.argv[2] if len(sys.argv) > 2 else None
    
    if command == "check":
        manager.check_prerequisites()
    elif command == "deploy":
        if vm_name:
            manager.deploy_vm(vm_name)
        else:
            manager.deploy_all()
    elif command == "start":
        if vm_name:
            manager.start_vm(vm_name)
        else:
            manager.start_all()
    elif command == "stop":
        if vm_name:
            manager.stop_vm(vm_name)
        else:
            manager.stop_all()
    elif command == "restart":
        if vm_name:
            manager.restart_vm(vm_name)
        else:
            manager.stop_all()
            time.sleep(10)
            manager.start_all()
    elif command == "status":
        status = manager.get_vm_status(vm_name)
        print(json.dumps(status, indent=2))
    elif command == "destroy":
        if vm_name:
            manager.destroy_vm(vm_name)
        else:
            print("Please specify VM name for destroy command")
    elif command == "reset":
        manager.reset_environment()
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()
