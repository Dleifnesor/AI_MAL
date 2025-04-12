#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL Scanner Module
====================

This module handles network scanning functionality using nmap.
"""

import os
import json
import subprocess
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime
from .logger import LoggerWrapper

class Scanner:
    """
    Scanner class for network scanning operations.
    """
    
    def __init__(self, target, scan_type="quick", stealth=False, services=False, 
                 version=False, os_detection=False, ports=None, timeout=None):
        """
        Initialize the scanner.
        
        Args:
            target (str): Target IP, hostname, or network range
            scan_type (str): Type of scan (quick, full, stealth)
            stealth (bool): Whether to use stealth mode
            services (bool): Whether to detect services
            version (bool): Whether to detect versions
            os_detection (bool): Whether to detect OS
            ports (str, optional): Ports to scan (default based on scan_type)
            timeout (int, optional): Scan timeout in seconds
        """
        self.target = target
        self.scan_type = scan_type
        self.stealth = stealth
        self.services = services
        self.version = version
        self.os_detection = os_detection
        self.ports = ports
        self.timeout = timeout
        self.logger = LoggerWrapper("Scanner")
        
        # Set default ports based on scan type
        if not self.ports:
            if scan_type == "quick":
                self.ports = "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
            elif scan_type == "full":
                self.ports = "1-65535"
            elif scan_type == "stealth":
                self.ports = "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
    
    def is_nmap_installed(self):
        """
        Check if nmap is installed.
        
        Returns:
            bool: True if nmap is installed, False otherwise
        """
        try:
            subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            return False
    
    def build_nmap_command(self):
        """
        Build the nmap command based on the scanner configuration.
        
        Returns:
            list: The nmap command as a list of arguments
        """
        cmd = ["nmap", "-oX", "-"]  # Output in XML format to stdout
        
        # Add scan type options
        if self.scan_type == "quick" or self.scan_type == "full":
            cmd.append("-sS")  # SYN scan
        elif self.scan_type == "stealth":
            cmd.append("-sS")  # Still SYN scan but with other stealth options
            cmd.append("-T2")  # Slower timing
            cmd.append("--data-length")  # Pad packets
            cmd.append("15")
        
        # Add stealth options if specified
        if self.stealth and self.scan_type != "stealth":
            cmd.append("-T2")  # Slower timing
            cmd.append("--data-length")  # Pad packets
            cmd.append("15")
        
        # Add service detection
        if self.services:
            cmd.append("-sV")
            
            # Add version detection intensity if version scanning is enabled
            if self.version:
                cmd.append("--version-intensity")
                cmd.append("7")  # Higher intensity for better version detection
        
        # Add OS detection
        if self.os_detection:
            cmd.append("-O")
        
        # Add ports
        cmd.append("-p")
        cmd.append(self.ports)
        
        # Add timeout if specified
        if self.timeout:
            cmd.append("--host-timeout")
            cmd.append(f"{self.timeout}s")
        
        # Add the target
        cmd.append(self.target)
        
        return cmd
    
    def parse_nmap_xml(self, xml_data):
        """
        Parse nmap XML output.
        
        Args:
            xml_data (str): Nmap XML output
        
        Returns:
            dict: Parsed scan results
        """
        root = ET.fromstring(xml_data)
        
        # Initialize the results dictionary
        results = {
            "scan_info": {
                "start_time": root.get("start", ""),
                "scan_type": self.scan_type,
                "target": self.target,
            },
            "hosts": []
        }
        
        # Parse each host
        for host in root.findall(".//host"):
            host_data = {
                "status": host.find("status").get("state", ""),
                "addresses": [],
                "hostnames": [],
                "ports": [],
                "os": []
            }
            
            # Get addresses
            for addr in host.findall(".//address"):
                host_data["addresses"].append({
                    "addr": addr.get("addr", ""),
                    "addrtype": addr.get("addrtype", ""),
                    "vendor": addr.get("vendor", "")
                })
            
            # Get hostnames
            for hostname in host.findall(".//hostname"):
                host_data["hostnames"].append({
                    "name": hostname.get("name", ""),
                    "type": hostname.get("type", "")
                })
            
            # Get ports and services
            for port in host.findall(".//port"):
                port_data = {
                    "protocol": port.get("protocol", ""),
                    "portid": port.get("portid", ""),
                    "state": port.find("state").get("state", "") if port.find("state") is not None else "",
                    "reason": port.find("state").get("reason", "") if port.find("state") is not None else "",
                    "service": {}
                }
                
                # Get service information if available
                service = port.find("service")
                if service is not None:
                    port_data["service"] = {
                        "name": service.get("name", ""),
                        "product": service.get("product", ""),
                        "version": service.get("version", ""),
                        "extrainfo": service.get("extrainfo", ""),
                        "cpe": [cpe.text for cpe in service.findall("cpe")]
                    }
                
                host_data["ports"].append(port_data)
            
            # Get OS information if available
            for os in host.findall(".//os"):
                for match in os.findall(".//osmatch"):
                    os_data = {
                        "name": match.get("name", ""),
                        "accuracy": match.get("accuracy", ""),
                        "osclass": []
                    }
                    
                    # Get OS class information
                    for osclass in match.findall(".//osclass"):
                        os_data["osclass"].append({
                            "type": osclass.get("type", ""),
                            "vendor": osclass.get("vendor", ""),
                            "osfamily": osclass.get("osfamily", ""),
                            "osgen": osclass.get("osgen", ""),
                            "accuracy": osclass.get("accuracy", ""),
                            "cpe": [cpe.text for cpe in osclass.findall("cpe")]
                        })
                    
                    host_data["os"].append(os_data)
            
            results["hosts"].append(host_data)
        
        return results
    
    def scan(self):
        """
        Perform a network scan.
        
        Returns:
            dict: Scan results
        """
        if not self.is_nmap_installed():
            self.logger.error("Nmap is not installed. Please install nmap to use this feature.")
            return {"error": "Nmap is not installed"}
        
        self.logger.info(f"Starting {self.scan_type} scan on {self.target}")
        
        # Build the nmap command
        cmd = self.build_nmap_command()
        self.logger.debug(f"Running command: {' '.join(cmd)}")
        
        try:
            # Run the nmap scan
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Nmap scan failed: {stderr.decode()}")
                return {"error": f"Nmap scan failed: {stderr.decode()}"}
            
            # Parse the XML output
            results = self.parse_nmap_xml(stdout.decode())
            
            # Add scan timestamp
            results["scan_info"]["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            self.logger.info(f"Scan completed. Found {len(results['hosts'])} hosts.")
            return results
            
        except Exception as e:
            self.logger.exception(f"Error during scanning: {str(e)}")
            return {"error": f"Error during scanning: {str(e)}"}
            
    def convert_ip_range(self, ip_range):
        """
        Convert various IP range formats to a list of IPs.
        
        Args:
            ip_range (str): IP range (e.g., 192.168.1.1-5, 192.168.1.0/24)
        
        Returns:
            list: List of IP addresses
        """
        try:
            # Check if it's a CIDR notation
            if "/" in ip_range:
                return [str(ip) for ip in ipaddress.ip_network(ip_range, strict=False).hosts()]
            
            # Check if it's a range (e.g., 192.168.1.1-5)
            elif "-" in ip_range:
                parts = ip_range.split("-")
                if "." in parts[1]:  # If the second part is a full IP
                    start_ip = ipaddress.ip_address(parts[0])
                    end_ip = ipaddress.ip_address(parts[1])
                    return [str(ipaddress.ip_address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]
                else:  # If the second part is just the last octet
                    base_ip = parts[0].rsplit(".", 1)[0]
                    start_octet = int(parts[0].rsplit(".", 1)[1])
                    end_octet = int(parts[1])
                    return [f"{base_ip}.{octet}" for octet in range(start_octet, end_octet + 1)]
            
            # Single IP
            else:
                return [ip_range]
                
        except Exception as e:
            self.logger.error(f"Error converting IP range: {str(e)}")
            return [ip_range]  # Return as is in case of error 

    def display_results(self, hosts):
        """
        Display scan results in a Rich formatted panel and table.
        
        Args:
            hosts (list): List of host dictionaries
        """
        try:
            from rich.panel import Panel
            from rich.table import Table
            from rich.console import Console
            from rich.box import DOUBLE_EDGE
            from rich.text import Text
            from rich import box
            
            if not hosts or len(hosts) == 0:
                console.print(Panel("[bold yellow]No hosts discovered[/bold yellow]", 
                                  title="Network Scan Results", 
                                  border_style="yellow",
                                  box=DOUBLE_EDGE))
                return
            
            # Create a table for the results
            table = Table(title="Discovered Hosts", box=box.DOUBLE_EDGE, show_header=True, header_style="bold cyan")
            table.add_column("IP Address", style="green")
            table.add_column("MAC Address", style="blue")
            table.add_column("Hostname", style="cyan")
            table.add_column("OS", style="magenta")
            table.add_column("Open Ports", style="yellow")
            
            # Process hosts to combine port information
            unique_hosts = {}
            for host in hosts:
                ip = host.get('ip', 'Unknown')
                if ip not in unique_hosts:
                    unique_hosts[ip] = {
                        'mac': host.get('mac', 'Unknown'),
                        'hostname': host.get('hostname', 'Unknown'),
                        'os': host.get('os', 'Unknown'),
                        'ports': []
                    }
                
                # Add port if it exists and not already in the list
                port = host.get('port')
                if port and port not in unique_hosts[ip]['ports']:
                    unique_hosts[ip]['ports'].append(port)
            
            # Add each host to the table
            for ip, host_info in unique_hosts.items():
                # Format ports list
                ports_str = ", ".join(sorted(host_info['ports'], key=lambda x: int(x.split('/')[0]) if '/' in x and x.split('/')[0].isdigit() else 0)) if host_info['ports'] else "None detected"
                
                table.add_row(
                    ip,
                    host_info['mac'],
                    host_info['hostname'],
                    host_info['os'],
                    ports_str
                )
            
            # Create panel to contain the table
            host_panel = Panel(
                table,
                title="[bold green]Network Scan Results[/bold green]",
                border_style="green",
                box=DOUBLE_EDGE
            )
            
            console.print(host_panel)
            
            # Display a summary of findings
            summary = f"[bold]Summary:[/bold] Found {len(unique_hosts)} hosts with {sum(len(h['ports']) for h in unique_hosts.values())} open ports"
            console.print(Panel(summary, border_style="blue"))
            
        except Exception as e:
            self.logger.error(f"Error displaying results: {e}")
            console.print(f"[red]Error displaying results: {e}[/red]")
            
            # Fallback to simple text display
            console.print("\n[bold]Discovered Hosts:[/bold]")
            for host in hosts:
                console.print(f"  IP: {host.get('ip', 'Unknown')}, Hostname: {host.get('hostname', 'Unknown')}")
                if 'port' in host and host['port']:
                    console.print(f"    Port: {host['port']}")

    def display_service_scan_results(self, hosts):
        """
        Display service scan results in a Rich formatted panel and table.
        
        Args:
            hosts (list): List of host dictionaries with service information
        """
        try:
            from rich.panel import Panel
            from rich.table import Table
            from rich.console import Console
            from rich.box import DOUBLE_EDGE
            from rich import box
            
            if not hosts or len(hosts) == 0:
                console.print(Panel("[bold yellow]No services discovered[/bold yellow]", 
                                  title="Service Scan Results", 
                                  border_style="yellow",
                                  box=DOUBLE_EDGE))
                return
            
            # Create a table for services
            service_table = Table(title="Discovered Services", box=box.DOUBLE_EDGE, show_header=True, header_style="bold cyan")
            service_table.add_column("IP Address", style="green")
            service_table.add_column("Port", style="yellow")
            service_table.add_column("Protocol", style="blue")
            service_table.add_column("Service", style="magenta")
            service_table.add_column("Version", style="cyan")
            
            # Process hosts
            for host in hosts:
                if 'port' in host and host['port'] and 'service' in host and host['service']:
                    # Parse port/protocol if in format "80/tcp"
                    port_str = host.get('port', '')
                    port = port_str
                    protocol = 'tcp'  # default
                    
                    if '/' in port_str:
                        parts = port_str.split('/')
                        port = parts[0]
                        protocol = parts[1]
                    
                    service_table.add_row(
                        host.get('ip', 'Unknown'),
                        port,
                        protocol,
                        host.get('service', 'Unknown'),
                        host.get('version', 'Unknown')
                    )
            
            # Create panel to contain the table
            service_panel = Panel(
                service_table,
                title="[bold blue]Service Detection Results[/bold blue]",
                border_style="blue",
                box=DOUBLE_EDGE
            )
            
            console.print(service_panel)
            
        except Exception as e:
            self.logger.error(f"Error displaying service results: {e}")
            console.print(f"[red]Error displaying service results: {e}[/red]")
            
            # Fallback to simple text display
            console.print("\n[bold]Discovered Services:[/bold]")
            for host in hosts:
                if 'port' in host and 'service' in host:
                    console.print(f"  IP: {host.get('ip', 'Unknown')}, Port: {host.get('port', 'Unknown')}, Service: {host.get('service', 'Unknown')}")

    def scan_network(self, target=None, scan_type='quick'):
        """
        Scan a network target.
        
        Args:
            target (str, optional): The target to scan. Defaults to self.target.
            scan_type (str, optional): The type of scan to perform. Defaults to 'quick'.
        
        Returns:
            list: List of discovered hosts
        """
        target = target or self.target
        
        # Create a rich Panel for the scan header
        from rich.panel import Panel
        from rich.text import Text
        
        header_text = Text.from_markup(f"[bold]Network Scan[/bold]\nTarget: [cyan]{target}[/cyan]\nScan Type: [yellow]{scan_type.upper()}[/yellow]")
        
        console.print(Panel(
            header_text,
            title="[bold blue]AI_MAL Network Scanner[/bold blue]",
            border_style="blue"
        ))
        
        # Display a progress indicator during the scan
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Scanning {target}...", total=None)
            
            try:
                # Parse target to determine scan approach
                if '/' in target:  # CIDR notation
                    progress.update(task, description=f"[cyan]Running network scan on {target}...")
                    # ... rest of the code remains the same ...
                # ... rest of the code remains the same ...
            
            except Exception as e:
                self.logger.exception(f"Error during scanning: {str(e)}")
                return []
        
        # After scan completes, display results
        if hosts:
            progress.update(task, description=f"[green]Scan completed! Found {len(hosts)} hosts")
        else:
            progress.update(task, description="[yellow]Scan completed! No hosts found")
        
        return hosts 