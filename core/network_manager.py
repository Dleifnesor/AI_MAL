"""Network interface manager for Kali Linux with IP/MAC spoofing capabilities."""

import subprocess
import random
import time
import logging
from typing import Optional, Tuple, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class NetworkInterface:
    """Network interface information."""
    name: str
    mac: str
    ip: str
    netmask: str
    gateway: str

class NetworkManager:
    """Manages network interfaces for Kali Linux with spoofing capabilities."""
    
    def __init__(self):
        """Initialize the network manager."""
        self.original_interfaces: List[NetworkInterface] = []
        self.current_interface: Optional[NetworkInterface] = None
        
    def get_network_interfaces(self) -> List[NetworkInterface]:
        """Get all available network interfaces."""
        interfaces = []
        try:
            # Get interface names
            result = subprocess.run(
                ['ip', 'link', 'show'],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.split('\n'):
                if ':' in line and '@' not in line:
                    iface_name = line.split(':')[1].strip()
                    if iface_name != 'lo':  # Skip loopback
                        interfaces.append(self._get_interface_info(iface_name))
                        
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting network interfaces: {e}")
            
        return interfaces
    
    def _get_interface_info(self, iface_name: str) -> NetworkInterface:
        """Get information about a specific network interface."""
        try:
            # Get MAC address
            mac_result = subprocess.run(
                ['ip', 'link', 'show', iface_name],
                capture_output=True,
                text=True,
                check=True
            )
            mac = mac_result.stdout.split('link/ether')[1].split()[0]
            
            # Get IP address and netmask
            ip_result = subprocess.run(
                ['ip', 'addr', 'show', iface_name],
                capture_output=True,
                text=True,
                check=True
            )
            ip_info = ip_result.stdout.split('inet')[1].split()[0]
            ip, netmask = ip_info.split('/')
            
            # Get default gateway
            gw_result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True,
                text=True,
                check=True
            )
            gateway = gw_result.stdout.split('via')[1].split()[0]
            
            return NetworkInterface(
                name=iface_name,
                mac=mac,
                ip=ip,
                netmask=netmask,
                gateway=gateway
            )
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting interface info for {iface_name}: {e}")
            raise
            
    def save_original_state(self):
        """Save the original network interface state."""
        self.original_interfaces = self.get_network_interfaces()
        
    def restore_original_state(self):
        """Restore the original network interface state."""
        if not self.original_interfaces:
            logger.warning("No original state to restore")
            return
            
        for iface in self.original_interfaces:
            self._restore_interface(iface)
            
    def _restore_interface(self, iface: NetworkInterface):
        """Restore a specific interface to its original state."""
        try:
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', iface.name, 'down'], check=True)
            
            # Restore MAC address
            subprocess.run(
                ['ip', 'link', 'set', iface.name, 'address', iface.mac],
                check=True
            )
            
            # Restore IP address
            subprocess.run(
                ['ip', 'addr', 'add', f"{iface.ip}/{iface.netmask}", 'dev', iface.name],
                check=True
            )
            
            # Bring interface up
            subprocess.run(['ip', 'link', 'set', iface.name, 'up'], check=True)
            
            # Restore default route
            subprocess.run(
                ['ip', 'route', 'add', 'default', 'via', iface.gateway],
                check=True
            )
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error restoring interface {iface.name}: {e}")
            
    def change_identity(self, iface_name: str) -> NetworkInterface:
        """Change the identity of a network interface (IP and MAC)."""
        try:
            # Generate random MAC address
            new_mac = ':'.join(['%02x' % random.randint(0, 255) for _ in range(6)])
            
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', iface_name, 'down'], check=True)
            
            # Change MAC address
            subprocess.run(
                ['ip', 'link', 'set', iface_name, 'address', new_mac],
                check=True
            )
            
            # Generate random IP in the same subnet
            iface = self._get_interface_info(iface_name)
            ip_parts = iface.ip.split('.')
            ip_parts[3] = str(random.randint(1, 254))
            new_ip = '.'.join(ip_parts)
            
            # Remove old IP and add new one
            subprocess.run(
                ['ip', 'addr', 'del', f"{iface.ip}/{iface.netmask}", 'dev', iface_name],
                check=True
            )
            subprocess.run(
                ['ip', 'addr', 'add', f"{new_ip}/{iface.netmask}", 'dev', iface_name],
                check=True
            )
            
            # Bring interface up
            subprocess.run(['ip', 'link', 'set', iface_name, 'up'], check=True)
            
            # Update default route
            subprocess.run(
                ['ip', 'route', 'del', 'default'],
                check=True
            )
            subprocess.run(
                ['ip', 'route', 'add', 'default', 'via', iface.gateway],
                check=True
            )
            
            # Wait for network to stabilize
            time.sleep(2)
            
            # Get updated interface info
            self.current_interface = self._get_interface_info(iface_name)
            return self.current_interface
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error changing interface identity: {e}")
            raise
            
    def get_current_interface(self) -> Optional[NetworkInterface]:
        """Get information about the current network interface."""
        return self.current_interface 