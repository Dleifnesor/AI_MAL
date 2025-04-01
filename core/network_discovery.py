"""Network discovery functionality for host detection."""

import logging
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Optional
import netifaces
import ipaddress

logger = logging.getLogger(__name__)

class NetworkDiscovery:
    """Class to handle network discovery and host detection."""
    
    def __init__(self, interface: Optional[str] = None):
        """Initialize network discovery.
        
        Args:
            interface: Network interface to use
        """
        self.interface = interface
        
    def get_all_hosts(self) -> List[str]:
        """Get a list of all hosts in the network.
        
        Returns:
            List of discovered host IP addresses
        """
        discovered_hosts = []
        
        # Determine target network
        target = self._get_target_network()
        if not target:
            logger.error("Failed to determine target network")
            return []
            
        # Try different discovery methods
        hosts = self._ping_sweep(target)
        if hosts:
            discovered_hosts.extend(hosts)
            
        if not discovered_hosts:
            hosts = self._syn_scan(target)
            if hosts:
                discovered_hosts.extend(hosts)
                
        if not discovered_hosts:
            hosts = self._udp_scan(target)
            if hosts:
                discovered_hosts.extend(hosts)
                
        return list(set(discovered_hosts))  # Remove duplicates
        
    def _get_target_network(self) -> Optional[str]:
        """Get target network in CIDR notation."""
        if not self.interface:
            # Try to find default interface
            try:
                gateways = netifaces.gateways()
                if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                    self.interface = gateways['default'][netifaces.AF_INET][1]
            except (ImportError, KeyError):
                logger.error("Failed to determine default interface")
                return None
                
        try:
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                netmask = addrs[netifaces.AF_INET][0]['netmask']
                
                # Calculate network in CIDR notation
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                return str(network)
            else:
                logger.error("No IPv4 address assigned to interface")
                return None
        except (ImportError, ValueError, KeyError) as e:
            logger.error(f"Failed to calculate network: {str(e)}")
            return None
            
    def _ping_sweep(self, target: str) -> List[str]:
        """Perform ping sweep to discover hosts."""
        discovered_hosts = []
        
        try:
            cmd = ["nmap", "-sn", target, "-oX", "-"]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Ping sweep failed: {stderr}")
                return []
                
            # Parse XML output
            try:
                tree = ET.fromstring(stdout)
                for host in tree.findall('.//host'):
                    status = host.find('status')
                    if status is not None and status.get('state') == 'up':
                        # Get the host's IP address
                        for addr in host.findall('address'):
                            if addr.get('addrtype') == 'ipv4':
                                discovered_hosts.append(addr.get('addr'))
                                break
            except Exception as e:
                logger.error(f"Failed to parse ping sweep results: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error during ping sweep: {str(e)}")
            
        return discovered_hosts
        
    def _syn_scan(self, target: str) -> List[str]:
        """Perform TCP SYN scan on common ports."""
        discovered_hosts = []
        
        try:
            cmd = ["nmap", "-sS", "-T4", "-F", target, "-oX", "-"]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"SYN scan failed: {stderr}")
                return []
                
            # Parse XML output
            try:
                tree = ET.fromstring(stdout)
                for host in tree.findall('.//host'):
                    status = host.find('status')
                    if status is not None and status.get('state') == 'up':
                        # Get the host's IP address
                        for addr in host.findall('address'):
                            if addr.get('addrtype') == 'ipv4':
                                discovered_hosts.append(addr.get('addr'))
                                break
            except Exception as e:
                logger.error(f"Failed to parse SYN scan results: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error during SYN scan: {str(e)}")
            
        return discovered_hosts
        
    def _udp_scan(self, target: str) -> List[str]:
        """Perform UDP scan on common ports."""
        discovered_hosts = []
        
        try:
            cmd = ["nmap", "-sU", "-T4", "-F", target, "-oX", "-"]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"UDP scan failed: {stderr}")
                return []
                
            # Parse XML output
            try:
                tree = ET.fromstring(stdout)
                for host in tree.findall('.//host'):
                    status = host.find('status')
                    if status is not None and status.get('state') == 'up':
                        # Get the host's IP address
                        for addr in host.findall('address'):
                            if addr.get('addrtype') == 'ipv4':
                                discovered_hosts.append(addr.get('addr'))
                                break
            except Exception as e:
                logger.error(f"Failed to parse UDP scan results: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error during UDP scan: {str(e)}")
            
        return discovered_hosts 