"""Direct Nmap scanner implementation with improved performance."""

import os
import time
import tempfile
import subprocess
from dataclasses import dataclass
from typing import Optional, Dict, Any
from lxml import etree
import logging

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Structured scan result data."""
    command: str
    scan_info: Dict[str, Any]
    scan_stats: Dict[str, Any]
    hosts: list
    elapsed: float

class DirectNmapScanner:
    """Direct implementation of nmap scanning using subprocess with improved performance."""
    
    def __init__(self, timeout: int = 300):
        """Initialize the scanner with a timeout."""
        self.timeout = timeout
        self._process_pool = []
        
    @staticmethod
    def check_nmap_installed() -> bool:
        """Check if nmap is installed and available on the system."""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=False
            )
            if result.returncode == 0:
                logger.debug(f"Nmap found: {result.stdout.strip()}")
                return True
            logger.error(f"Nmap check failed: {result.stderr}")
            return False
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Nmap not found or not executable: {e}")
            return False

    def scan(self, hosts: str, arguments: str) -> Optional[ScanResult]:
        """Run an nmap scan using subprocess and return results in a structured format.
        
        Args:
            hosts: Target IP address or hostname
            arguments: Nmap command line arguments as a string
            
        Returns:
            ScanResult object with structured scan data, or None if scan fails
        """
        if not self.check_nmap_installed():
            logger.error("Nmap is not installed on this system")
            return None
            
        # Create temporary file for XML output
        fd, xml_output = tempfile.mkstemp(suffix='.xml', prefix='nmap_')
        os.close(fd)
        
        try:
            # Build command
            cmd = ['nmap', '-oX', xml_output]
            
            # Add all arguments except target
            if arguments:
                args_list = arguments.split()
                for arg in args_list:
                    if arg != hosts:  # Avoid adding target twice
                        cmd.append(arg)
            
            # Add target last
            cmd.append(hosts)
            
            # Log the command
            logger.debug(f"Running nmap command: {' '.join(cmd)}")
            
            # Run scan with timeout
            start_time = time.time()
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait for process with timeout
            while True:
                if time.time() - start_time > self.timeout:
                    process.terminate()
                    logger.error("Nmap scan timed out after %d seconds", self.timeout)
                    return None
                    
                if process.poll() is not None:
                    break
                    
                time.sleep(0.1)
            
            # Get output
            stdout, stderr = process.communicate()
            elapsed = time.time() - start_time
            
            # Check for errors
            if process.returncode != 0:
                logger.error(f"Nmap scan failed with return code {process.returncode}")
                logger.error(f"Error: {stderr}")
                return None
                
            # Parse XML output using lxml for better performance
            try:
                tree = etree.parse(xml_output)
                root = tree.getroot()
                
                # Extract scan info
                scan_info = {}
                for scaninfo in root.findall('.//scaninfo'):
                    protocol = scaninfo.get('protocol', 'unknown')
                    scan_info[protocol] = {
                        'method': scaninfo.get('type', ''),
                        'services': scaninfo.get('services', '')
                    }
                
                # Extract scan stats
                scan_stats = {}
                finished = root.find('.//runstats/finished')
                if finished is not None:
                    scan_stats['finished'] = {
                        'time': finished.get('timestr', ''),
                        'elapsed': finished.get('elapsed', '0')
                    }
                
                hosts = root.find('.//runstats/hosts')
                if hosts is not None:
                    scan_stats['hosts'] = {
                        'up': hosts.get('up', '0'),
                        'down': hosts.get('down', '0'),
                        'total': hosts.get('total', '0')
                    }
                
                # Process hosts
                host_list = []
                for host in root.findall('.//host'):
                    host_data = self._parse_host(host)
                    if host_data:
                        host_list.append(host_data)
                
                return ScanResult(
                    command=' '.join(cmd),
                    scan_info=scan_info,
                    scan_stats=scan_stats,
                    hosts=host_list,
                    elapsed=elapsed
                )
                
            except etree.ParseError as e:
                logger.error(f"Error parsing Nmap XML output: {e}")
                return None
                
        except Exception as e:
            logger.error(f"Error running nmap scan: {e}")
            return None
        finally:
            # Clean up temporary file
            try:
                os.unlink(xml_output)
            except:
                pass
    
    def _parse_host(self, host_elem) -> Optional[Dict[str, Any]]:
        """Parse a host element from the XML output."""
        try:
            host_data = {
                'addresses': [],
                'hostnames': [],
                'ports': [],
                'os': None,
                'status': None
            }
            
            # Get addresses
            for addr in host_elem.findall('address'):
                host_data['addresses'].append({
                    'type': addr.get('addrtype', ''),
                    'addr': addr.get('addr', ''),
                    'vendor': addr.get('vendor', '')
                })
            
            # Get hostnames
            for hostname in host_elem.findall('hostnames/hostname'):
                host_data['hostnames'].append({
                    'name': hostname.get('name', ''),
                    'type': hostname.get('type', '')
                })
            
            # Get status
            status = host_elem.find('status')
            if status is not None:
                host_data['status'] = {
                    'state': status.get('state', ''),
                    'reason': status.get('reason', '')
                }
            
            # Get ports
            for port in host_elem.findall('ports/port'):
                port_data = self._parse_port(port)
                if port_data:
                    host_data['ports'].append(port_data)
            
            # Get OS detection
            os_matches = host_elem.find('os')
            if os_matches is not None:
                os_data = self._parse_os_matches(os_matches)
                if os_data:
                    host_data['os'] = os_data
            
            return host_data
            
        except Exception as e:
            logger.error(f"Error parsing host element: {e}")
            return None
    
    def _parse_port(self, port_elem) -> Optional[Dict[str, Any]]:
        """Parse a port element from the XML output."""
        try:
            port_data = {
                'id': port_elem.get('portid', ''),
                'protocol': port_elem.get('protocol', ''),
                'state': None,
                'service': None
            }
            
            # Get port state
            state = port_elem.find('state')
            if state is not None:
                port_data['state'] = {
                    'state': state.get('state', ''),
                    'reason': state.get('reason', '')
                }
            
            # Get service info
            service = port_elem.find('service')
            if service is not None:
                port_data['service'] = {
                    'name': service.get('name', ''),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'extrainfo': service.get('extrainfo', ''),
                    'conf': service.get('conf', '')
                }
            
            return port_data
            
        except Exception as e:
            logger.error(f"Error parsing port element: {e}")
            return None
    
    def _parse_os_matches(self, os_elem) -> Optional[list]:
        """Parse OS detection matches from the XML output."""
        try:
            os_data = []
            for osmatch in os_elem.findall('osmatch'):
                match = {
                    'name': osmatch.get('name', ''),
                    'accuracy': osmatch.get('accuracy', ''),
                    'classes': []
                }
                
                for osclass in osmatch.findall('osclass'):
                    match['classes'].append({
                        'type': osclass.get('type', ''),
                        'vendor': osclass.get('vendor', ''),
                        'osfamily': osclass.get('osfamily', ''),
                        'osgen': osclass.get('osgen', ''),
                        'accuracy': osclass.get('accuracy', '')
                    })
                
                os_data.append(match)
            
            return os_data if os_data else None
            
        except Exception as e:
            logger.error(f"Error parsing OS matches: {e}")
            return None 