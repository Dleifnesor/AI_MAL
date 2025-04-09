import os
import subprocess
import logging
import json
import time
import socket
import netifaces
import nmap
import psutil
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path

logger = logging.getLogger("AI_MAL.network_scanner")

class NetworkScanner:
    def __init__(self, scan_config: Dict[str, Any]):
        """
        Initialize the network scanner with the given configuration.
        
        Args:
            scan_config: A dictionary containing scan configuration parameters.
        """
        self.scan_config = scan_config
        self.target = scan_config.get("target")
        self.interface = scan_config.get("interface")
        self.scan_type = scan_config.get("scan_type", "basic")
        self.ports = scan_config.get("ports", "1-1000")
        self.timeout = scan_config.get("timeout", 120)
        self.max_retries = scan_config.get("max_retries", 2)
        self.results_dir = Path(scan_config.get("results_dir", "scan_results"))
        self.nm = nmap.PortScanner()
        self.last_scan_result = None
        
        # Ensure results directory exists
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Get all available network interfaces if none specified
        if not self.interface:
            self.interface = self._get_first_active_interface()
            logger.info(f"No interface specified, using: {self.interface}")
            
    def _get_first_active_interface(self) -> Optional[str]:
        """
        Get the first active non-loopback interface.
        
        Returns:
            The name of the first active interface or None if none found.
        """
        try:
            # Get all network interfaces that are up and not loopback or docker
            interfaces = []
            for iface in netifaces.interfaces():
                # Skip loopback and docker interfaces
                if iface == 'lo' or iface.startswith('docker') or iface.startswith('veth'):
                    continue
                
                # Check if interface has IPv4 address and is up
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    interfaces.append(iface)
            
            if interfaces:
                logger.info(f"Found active interfaces: {', '.join(interfaces)}")
                return interfaces[0]
            else:
                logger.warning("No active network interfaces found")
                return None
                
        except Exception as e:
            logger.error(f"Error getting network interfaces: {str(e)}")
            return None
            
    def _prepare_scan_arguments(self) -> Dict[str, Any]:
        """
        Prepare scan arguments based on the scan configuration.
        
        Returns:
            A dictionary of scan arguments to pass to nmap.
        """
        args = {}
        
        # Add basic scan arguments
        if self.interface:
            args['arguments'] = f'-e {self.interface}'
        else:
            args['arguments'] = ''
            
        # Configure scan type (intensity)
        if self.scan_type == "aggressive":
            args['arguments'] += ' -A -T4'
        elif self.scan_type == "stealthy":
            args['arguments'] += ' -sS -T2'
        else:  # basic
            args['arguments'] += ' -sS -T3'
            
        # Configure service and version detection
        if self.scan_config.get("service_detection", False):
            args['arguments'] += ' -sV'
            
        # Configure OS detection
        if self.scan_config.get("os_detection", False):
            args['arguments'] += ' -O'
            
        # Configure script scans
        if self.scan_config.get("script_scan", False):
            args['arguments'] += ' --script=default'
        
        # Configure vulnerability detection
        if self.scan_config.get("vuln_detection", False):
            args['arguments'] += ' --script=vuln'
            
        # Configure timeout
        if self.timeout:
            args['arguments'] += f' --host-timeout {self.timeout}s'
            
        # Configure packet tracing for debugging
        if self.scan_config.get("packet_trace", False):
            args['arguments'] += ' --packet-trace'
            
        # Add any custom arguments
        if self.scan_config.get("custom_args"):
            args['arguments'] += f" {self.scan_config['custom_args']}"
            
        logger.info(f"Prepared scan arguments: {args['arguments']}")
        return args
    
    def scan(self) -> Dict[str, Any]:
        """
        Perform a network scan based on the configuration.
        
        Returns:
            A dictionary containing the scan results.
        """
        if not self.target:
            logger.error("No target specified for scanning")
            return {"error": "No target specified"}
            
        # Try to verify target is reachable before scanning
        if not self._is_host_reachable():
            logger.warning(f"Target {self.target} appears to be unreachable. Scan may fail.")
        
        # Prepare scan arguments
        scan_args = self._prepare_scan_arguments()
        
        # Track failures for retry logic
        failures = 0
        result = None
        
        while failures <= self.max_retries:
            try:
                logger.info(f"Scanning target {self.target} (ports: {self.ports})...")
                start_time = time.time()
                
                # Run the scan
                result = self.nm.scan(
                    hosts=self.target,
                    ports=self.ports,
                    **scan_args
                )
                
                scan_time = time.time() - start_time
                logger.info(f"Scan completed in {scan_time:.2f} seconds")
                
                # Check if scan was successful
                if self.target in self.nm.all_hosts():
                    # Save scan result
                    self.last_scan_result = result
                    self._save_scan_result(result)
                    return self._process_scan_result(result)
                else:
                    logger.warning(f"Target {self.target} not found in scan results")
                    failures += 1
                    
            except nmap.PortScannerError as e:
                logger.error(f"Nmap scan error: {str(e)}")
                failures += 1
                
            except Exception as e:
                logger.error(f"Unexpected error during scan: {str(e)}")
                failures += 1
                
            # If we have more retries, wait before trying again
            if failures <= self.max_retries:
                retry_delay = failures * 5  # Progressive backoff
                logger.info(f"Retrying scan in {retry_delay} seconds... (Attempt {failures}/{self.max_retries})")
                time.sleep(retry_delay)
        
        # If we get here, all scan attempts failed
        logger.error(f"All scan attempts failed after {failures} tries")
        return {
            "error": "Scan failed after maximum retries",
            "target": self.target,
            "raw_result": result if result else None
        }
    
    def _is_host_reachable(self) -> bool:
        """
        Check if the target host is reachable before scanning.
        
        Returns:
            True if the host is reachable, False otherwise.
        """
        try:
            # Try to establish a TCP connection to common ports
            for port in [80, 443, 22]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    logger.info(f"Target {self.target} is reachable on port {port}")
                    return True
            
            # If TCP connect failed, try ICMP ping
            ping_cmd = ['ping', '-c', '1', '-W', '3', self.target]
            with open(os.devnull, 'w') as devnull:
                result = subprocess.call(ping_cmd, stdout=devnull, stderr=devnull)
            
            if result == 0:
                logger.info(f"Target {self.target} responded to ping")
                return True
            else:
                logger.warning(f"Target {self.target} did not respond to ping or common TCP ports")
                return False
                
        except Exception as e:
            logger.warning(f"Error checking if host is reachable: {str(e)}")
            return False
    
    def _process_scan_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process the scan result to extract relevant information.
        
        Args:
            result: The raw scan result from nmap.
            
        Returns:
            A processed dictionary with relevant scan information.
        """
        if not result or 'scan' not in result:
            logger.warning("Invalid scan result")
            return {"error": "Invalid scan result"}
            
        processed_result = {
            "target": self.target,
            "scan_time": result.get('nmap', {}).get('scanstats', {}).get('elapsed', '0'),
            "hosts_up": 0,
            "hosts": []
        }
        
        # Process each host in scan results
        for host, host_data in result.get('scan', {}).items():
            host_info = {
                "ip": host,
                "status": host_data.get('status', {}).get('state', 'unknown'),
                "hostname": self._get_hostname(host_data),
                "ports": self._get_ports(host_data),
                "os": self._get_os_info(host_data),
                "services": self._get_services(host_data)
            }
            
            if host_info["status"] == "up":
                processed_result["hosts_up"] += 1
                
            processed_result["hosts"].append(host_info)
        
        return processed_result
    
    def _get_hostname(self, host_data: Dict[str, Any]) -> str:
        """
        Extract hostname from host data.
        
        Args:
            host_data: Host data from nmap scan.
            
        Returns:
            Hostname or empty string if not found.
        """
        if 'hostnames' in host_data and host_data['hostnames']:
            for hostname in host_data['hostnames']:
                if hostname.get('name'):
                    return hostname.get('name')
        return ""
    
    def _get_ports(self, host_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract port information from host data.
        
        Args:
            host_data: Host data from nmap scan.
            
        Returns:
            List of dictionaries containing port information.
        """
        ports = []
        if 'tcp' in host_data:
            for port_num, port_data in host_data['tcp'].items():
                ports.append({
                    "number": port_num,
                    "protocol": "tcp",
                    "state": port_data.get('state', 'unknown'),
                    "service": port_data.get('name', 'unknown'),
                    "product": port_data.get('product', ''),
                    "version": port_data.get('version', '')
                })
                
        if 'udp' in host_data:
            for port_num, port_data in host_data['udp'].items():
                ports.append({
                    "number": port_num,
                    "protocol": "udp",
                    "state": port_data.get('state', 'unknown'),
                    "service": port_data.get('name', 'unknown'),
                    "product": port_data.get('product', ''),
                    "version": port_data.get('version', '')
                })
                
        return ports
    
    def _get_os_info(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract OS information from host data.
        
        Args:
            host_data: Host data from nmap scan.
            
        Returns:
            Dictionary containing OS information.
        """
        os_info = {"name": "Unknown", "accuracy": "0", "cpe": ""}
        
        if 'osmatch' in host_data and host_data['osmatch']:
            best_match = host_data['osmatch'][0]
            os_info = {
                "name": best_match.get('name', 'Unknown'),
                "accuracy": best_match.get('accuracy', '0'),
                "cpe": best_match.get('osclass', [{}])[0].get('cpe', [''])[0] if 'osclass' in best_match and best_match['osclass'] else ''
            }
            
        return os_info
    
    def _get_services(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Identify key services running on the host.
        
        Args:
            host_data: Host data from nmap scan.
            
        Returns:
            Dictionary mapping service types to port numbers.
        """
        services = {
            "web": [],
            "ssh": [],
            "ftp": [],
            "database": [],
            "mail": [],
            "dns": [],
            "other": []
        }
        
        for protocol in ['tcp', 'udp']:
            if protocol in host_data:
                for port_num, port_data in host_data[protocol].items():
                    service_name = port_data.get('name', '').lower()
                    
                    if service_name in ['http', 'https', 'www']:
                        services["web"].append(f"{port_num}/{protocol}")
                    elif service_name == 'ssh':
                        services["ssh"].append(f"{port_num}/{protocol}")
                    elif service_name in ['ftp', 'ftps', 'sftp']:
                        services["ftp"].append(f"{port_num}/{protocol}")
                    elif service_name in ['mysql', 'postgresql', 'mongodb', 'redis', 'cassandra', 'mssql', 'oracle']:
                        services["database"].append(f"{port_num}/{protocol}")
                    elif service_name in ['smtp', 'pop3', 'imap', 'exchange']:
                        services["mail"].append(f"{port_num}/{protocol}")
                    elif service_name in ['dns', 'domain']:
                        services["dns"].append(f"{port_num}/{protocol}")
                    else:
                        services["other"].append(f"{port_num}/{protocol} ({service_name})")
                        
        # Remove empty categories
        return {k: v for k, v in services.items() if v}
    
    def _save_scan_result(self, result: Dict[str, Any]) -> None:
        """
        Save the scan result to a file.
        
        Args:
            result: The scan result to save.
        """
        try:
            # Create a unique filename based on target and timestamp
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"{self.target.replace('.', '_')}_{timestamp}.json"
            filepath = self.results_dir / filename
            
            # Save the result as JSON
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=2)
                
            logger.info(f"Scan result saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving scan result: {str(e)}")
    
    def get_processed_results(self) -> Dict[str, Any]:
        """
        Get the processed results of the last scan.
        
        Returns:
            Processed scan results or error message if no results available.
        """
        if self.last_scan_result:
            return self._process_scan_result(self.last_scan_result)
        else:
            return {"error": "No scan results available"} 