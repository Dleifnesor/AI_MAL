#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL Vulnerability Scanner Module
==================================

This module handles vulnerability scanning using OpenVAS or nmap NSE scripts.
"""

import os
import json
import time
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from .logger import LoggerWrapper
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

# Initialize rich console
console = Console()

class VulnerabilityScanner:
    """
    Vulnerability scanner class that uses OpenVAS for comprehensive vulnerability scanning.
    """
    
    def __init__(self, target, scan_config="full_and_fast", timeout=3600, custom_vuln_file=None, use_nmap=False, gmp_connection=None):
        """
        Initialize the vulnerability scanner.
        
        Args:
            target (str): Target IP, hostname, or network range
            scan_config (str): OpenVAS scan configuration type
            timeout (int): Scan timeout in seconds
            custom_vuln_file (str, optional): Path to custom vulnerability file
            use_nmap (bool): Whether to use nmap instead of OpenVAS (default: False)
            gmp_connection (str, optional): GMP connection string
        """
        self.target = target
        self.scan_config = scan_config
        self.timeout = timeout
        self.custom_vuln_file = custom_vuln_file
        self.use_nmap = use_nmap
        self.gmp_connection = gmp_connection
        self.logger = LoggerWrapper("VulnScanner")
        
        # Define OpenVAS scan configurations
        self.openvas_configs = {
            "full_and_fast": "daba56c8-73ec-11df-a475-002264764cea",
            "full_and_fast_ultimate": "698f691e-7489-11df-9d8c-002264764cea",
            "full_and_very_deep": "708f25c4-7489-11df-8094-002264764cea",
            "full_and_very_deep_ultimate": "74db13d6-7489-11df-91b9-002264764cea",
            "system_discovery": "8715c877-47a0-438d-98a3-27c7a6ab2196",
            "system_discovery_ultimate": "bbca7412-a950-11e3-9109-406186ea4fc5"
        }
        
        # Load custom vulnerabilities if file is provided
        if self.custom_vuln_file:
            self.load_custom_vulnerabilities()
    
    def load_custom_vulnerabilities(self):
        """
        Load custom vulnerabilities from file.
        """
        try:
            with open(self.custom_vuln_file, 'r') as f:
                self.custom_vulns = json.load(f)
            self.logger.info(f"Loaded {len(self.custom_vulns)} custom vulnerabilities from {self.custom_vuln_file}")
        except Exception as e:
            self.logger.error(f"Error loading custom vulnerabilities: {str(e)}")
            self.custom_vulns = []
    
    def is_openvas_available(self):
        """Check if OpenVAS services are running and accessible."""
        try:
            # Check if ospd-openvas service is running
            result = subprocess.run(
                ["systemctl", "is-active", "ospd-openvas"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if result.returncode != 0:
                self.logger.warning("ospd-openvas service is not running")
                return False

            # Check if gvmd service is running
            result = subprocess.run(
                ["systemctl", "is-active", "gvmd"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if result.returncode != 0:
                self.logger.warning("gvmd service is not running")
                return False

            # Try to connect using OSP protocol with the current user
            try:
                # First try the standard socket path
                result = subprocess.run(
                    ["gvm-cli", "--protocol", "OSP", "socket", "--sockpath", "/run/ospd/ospd.sock", "--xml", "<help/>"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    user=os.getenv('SUDO_USER', os.getenv('USER'))
                )
                
                if result.returncode == 0:
                    return True
                
                # If that fails, try the alternative socket path
                result = subprocess.run(
                    ["gvm-cli", "--protocol", "OSP", "socket", "--sockpath", "/var/run/ospd/ospd.sock", "--xml", "<help/>"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    user=os.getenv('SUDO_USER', os.getenv('USER'))
                )
                if result.returncode == 0:
                    return True
                
                # If both fail, try to get the socket path from the service
                result = subprocess.run(
                    ["systemctl", "show", "ospd-openvas", "--property=ExecStart"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                if result.returncode == 0:
                    output = result.stdout.decode()
                    if "--socket-path" in output:
                        socket_path = output.split("--socket-path")[1].split()[0]
                        result = subprocess.run(
                            ["gvm-cli", "--protocol", "OSP", "socket", "--sockpath", socket_path, "--xml", "<help/>"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=5,
                            user=os.getenv('SUDO_USER', os.getenv('USER'))
                        )
                        if result.returncode == 0:
                            return True
                
                return False
                
            except Exception as e:
                self.logger.warning(f"Error checking OSP connection: {e}")
                return False
            
        except Exception as e:
            self.logger.error(f"Error checking OpenVAS availability: {e}")
            return False

    def connect_to_openvas(self):
        """Connect to OpenVAS and return the connection object."""
        try:
            # Check if OpenVAS services are running
            if not self.is_openvas_available():
                self.logger.warning("OpenVAS services not available")
                return None
            
            # Try to connect using OSP protocol with the current user
            try:
                # First try the standard socket path
                result = subprocess.run(
                    ["gvm-cli", "--protocol", "OSP", "socket", "--sockpath", "/run/ospd/ospd.sock", "--xml", "<help/>"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    user=os.getenv('SUDO_USER', os.getenv('USER'))
                )
                
                if result.returncode == 0:
                    self.logger.info("Connected to OpenVAS using standard socket path")
                    return True
                
                # If that fails, try the alternative socket path
                result = subprocess.run(
                    ["gvm-cli", "--protocol", "OSP", "socket", "--sockpath", "/var/run/ospd/ospd.sock", "--xml", "<help/>"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    user=os.getenv('SUDO_USER', os.getenv('USER'))
                )
                if result.returncode == 0:
                    self.logger.info("Connected to OpenVAS using alternative socket path")
                    return True
                
                # If both fail, try to get the socket path from the service
                result = subprocess.run(
                    ["systemctl", "show", "ospd-openvas", "--property=ExecStart"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                if result.returncode == 0:
                    output = result.stdout.decode()
                    if "--socket-path" in output:
                        socket_path = output.split("--socket-path")[1].split()[0]
                        result = subprocess.run(
                            ["gvm-cli", "--protocol", "OSP", "socket", "--sockpath", socket_path, "--xml", "<help/>"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=5,
                            user=os.getenv('SUDO_USER', os.getenv('USER'))
                        )
                        if result.returncode == 0:
                            self.logger.info(f"Connected to OpenVAS using service socket path: {socket_path}")
                            return True
                
                self.logger.warning("Could not connect to OpenVAS")
                return None
                
            except Exception as e:
                self.logger.error(f"Error connecting to OpenVAS: {e}")
                return None
            
        except Exception as e:
            self.logger.error(f"Error in connect_to_openvas: {e}")
            return None
    
    def display_scan_results(self, results):
        """Display scan results in a formatted table."""
        try:
            if not results:
                print("[!] No hosts discovered")
                return
            
            # Create a table for the results
            table = Table(title="Discovered Hosts", show_header=True, header_style="bold magenta")
            table.add_column("IP Address", style="cyan")
            table.add_column("Hostname", style="green")
            table.add_column("OS", style="yellow")
            table.add_column("Open Ports", style="blue")
            
            # Add each host to the table
            for host in results:
                # Ensure all values are strings and handle None/empty values
                ip = str(host.get('ip', 'Unknown')).strip() or 'Unknown'
                hostname = str(host.get('hostname', 'Unknown')).strip() or 'Unknown'
                os_info = str(host.get('os', 'Unknown')).strip() or 'Unknown'
                
                # Handle ports list
                ports = host.get('ports', [])
                if isinstance(ports, list):
                    ports_str = ', '.join(str(p).strip() for p in ports if p)
                else:
                    ports_str = str(ports).strip()
                ports_str = ports_str or 'None'
                
                # Add row to table
                table.add_row(ip, hostname, os_info, ports_str)
            
            # Print the table
            print(table)
            
        except Exception as e:
            print(f"[!] Error displaying results: {e}")
            # Fallback to simple text display
            print("\nDiscovered Hosts:")
            for host in results:
                ip = str(host.get('ip', 'Unknown')).strip() or 'Unknown'
                hostname = str(host.get('hostname', 'Unknown')).strip() or 'Unknown'
                os_info = str(host.get('os', 'Unknown')).strip() or 'Unknown'
                ports = host.get('ports', [])
                if isinstance(ports, list):
                    ports_str = ', '.join(str(p).strip() for p in ports if p)
                else:
                    ports_str = str(ports).strip()
                ports_str = ports_str or 'None'
                
                print(f"IP: {ip}")
                print(f"Hostname: {hostname}")
                print(f"OS: {os_info}")
                print(f"Open Ports: {ports_str}")
                print("---")

    def display_vulnerabilities(self, vulnerabilities):
        """Display vulnerabilities in a formatted table."""
        try:
            if not vulnerabilities:
                print("[!] No vulnerabilities found")
                return
            
            # Create a table for the results
            table = Table(title="Discovered Vulnerabilities", show_header=True, header_style="bold magenta")
            table.add_column("Host", style="cyan")
            table.add_column("Port", style="green")
            table.add_column("Service", style="yellow")
            table.add_column("Vulnerability", style="blue")
            table.add_column("Severity", style="red")
            
            # Add each vulnerability to the table
            for vuln in vulnerabilities:
                # Ensure all values are strings and handle None/empty values
                host = str(vuln.get('host', 'Unknown')).strip() or 'Unknown'
                port = str(vuln.get('port', 'Unknown')).strip() or 'Unknown'
                service = str(vuln.get('service', 'Unknown')).strip() or 'Unknown'
                name = str(vuln.get('name', 'Unknown')).strip() or 'Unknown'
                severity = str(vuln.get('severity', 'Unknown')).strip() or 'Unknown'
                
                # Add row to table
                table.add_row(host, port, service, name, severity)
            
            # Print the table
            print(table)
            
        except Exception as e:
            print(f"[!] Error displaying vulnerabilities: {e}")
            # Fallback to simple text display
            print("\nDiscovered Vulnerabilities:")
            for vuln in vulnerabilities:
                host = str(vuln.get('host', 'Unknown')).strip() or 'Unknown'
                port = str(vuln.get('port', 'Unknown')).strip() or 'Unknown'
                service = str(vuln.get('service', 'Unknown')).strip() or 'Unknown'
                name = str(vuln.get('name', 'Unknown')).strip() or 'Unknown'
                severity = str(vuln.get('severity', 'Unknown')).strip() or 'Unknown'
                
                print(f"Host: {host}")
                print(f"Port: {port}")
                print(f"Service: {service}")
                print(f"Vulnerability: {name}")
                print(f"Severity: {severity}")
                print("---")

    def scan_with_openvas(self):
        """
        Perform a vulnerability scan using OpenVAS.
        
        Returns:
            dict: Scan results
        """
        self.logger.info(f"Starting OpenVAS vulnerability scan on {self.target}")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Connecting to OpenVAS...", total=None)
                
                # Check if OpenVAS services are running
                if not self.is_openvas_available():
                    progress.update(task, description="[red]OpenVAS services not available")
                    return []
                    
                progress.update(task, description="[cyan]Creating OpenVAS target...")
                
                # Create target using OSP protocol
                target_id = self.create_target_ospd()
                if not target_id:
                    progress.update(task, description="[red]Failed to create target")
                    return []
                    
                progress.update(task, description="[cyan]Creating scan task...")
                
                # Create task using OSP protocol
                task_id = self.create_task_ospd(target_id)
                if not task_id:
                    progress.update(task, description="[red]Failed to create task")
                    return []
                    
                progress.update(task, description="[cyan]Starting vulnerability scan...")
                
                # Start scan using OSP protocol
                if not self.start_task_ospd(task_id):
                    progress.update(task, description="[red]Failed to start task")
                    return []
                    
                progress.update(task, description="[cyan]Scan in progress...")
                
                # Monitor scan progress
                while True:
                    status = self.get_task_status_ospd(task_id)
                    if status == "Done":
                        progress.update(task, description="[green]Scan completed!")
                        break
                    elif status == "Failed":
                        progress.update(task, description="[red]Scan failed!")
                        return []
                    time.sleep(10)
                    
                # Get results
                progress.update(task, description="[cyan]Retrieving scan results...")
                results = self.get_scan_results_ospd(task_id)
                
                # Display results
                if results:
                    self.display_vulnerabilities(results)
                    
                return results
                
        except Exception as e:
            self.logger.error(f"Error during OpenVAS scan: {e}")
            return []
    
    def scan_with_nmap(self):
        """
        Perform a vulnerability scan using nmap NSE scripts.
        
        Returns:
            dict: Scan results
        """
        self.logger.info(f"Starting nmap vulnerability scan on {self.target}")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Starting nmap vulnerability scan...", total=None)
                
                # Run nmap scan
                results = self.run_nmap_scan()
                
                progress.update(task, description="[green]Nmap scan completed!")
                
                # Display results in a table
                if results:
                    self.display_nmap_results_table(results)
                    
                return results
                
        except Exception as e:
            self.logger.error(f"Error during nmap scan: {e}")
            return []
            
    def display_nmap_results_table(self, results):
        """Display nmap scan results in a rich table."""
        table = Table(title="[bold red]Nmap Vulnerability Scan Results[/bold red]")
        table.add_column("Host", style="cyan")
        table.add_column("Port", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Vulnerability", style="red")
        table.add_column("Severity", style="magenta")
        
        for result in results:
            table.add_row(
                result.get('host', 'N/A'),
                str(result.get('port', 'N/A')),
                result.get('service', 'N/A'),
                result.get('name', 'N/A'),
                result.get('severity', 'N/A')
            )
            
        console.print(Panel(table, title="[bold]Nmap Scan Results[/bold]"))
    
    def scan(self):
        """
        Perform vulnerability scanning based on configuration.
        
        Returns:
            dict: Scan results
        """
        if self.use_nmap:
            self.logger.info("Using nmap for vulnerability scanning")
            return self.scan_with_nmap()
        else:
            self.logger.info("Using OpenVAS for vulnerability scanning")
            return self.scan_with_openvas()
    
    def get_cve_details(self, cve_id):
        """
        Get details for a specific CVE ID.
        
        Args:
            cve_id (str): The CVE ID to look up
        
        Returns:
            dict: CVE details
        """
        try:
            # Try to get CVE details from the NIST NVD API
            import requests
            api_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
            response = requests.get(api_url)
            
            if response.status_code == 200:
                data = response.json()
                if "result" in data:
                    cve_item = data["result"]["CVE_Items"][0]
                    return {
                        "id": cve_id,
                        "description": cve_item["cve"]["description"]["description_data"][0]["value"],
                        "severity": cve_item["impact"]["baseMetricV2"]["severity"] if "baseMetricV2" in cve_item["impact"] else "N/A",
                        "cvss_score": cve_item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"] if "baseMetricV2" in cve_item["impact"] else "N/A",
                        "published_date": cve_item["publishedDate"],
                        "last_modified": cve_item["lastModifiedDate"]
                    }
            
            # If API request fails, return basic info
            return {"id": cve_id, "description": "Details not available", "severity": "N/A"}
            
        except Exception as e:
            self.logger.warning(f"Error retrieving CVE details for {cve_id}: {str(e)}")
            return {"id": cve_id, "description": "Details not available", "severity": "N/A"}
    
    def create_target_ospd(self):
        """Create a target in OpenVAS using OSP protocol."""
        try:
            import xml.etree.ElementTree as ET
            
            # Create target XML
            target_xml = f"""
            <create_target>
                <name>AI_MAL_Target_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}</name>
                <hosts>{self.target}</hosts>
                <comment>Created by AI_MAL</comment>
            </create_target>
            """
            
            # Send request using OSP protocol
            result = subprocess.run(
                ["gvm-cli", "--protocol", "OSP", "socket", "--sockpath", "/run/ospd/ospd.sock", "--xml", target_xml],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            if result.returncode == 0:
                root = ET.fromstring(result.stdout.decode())
                return root.get('id')
            return None
        except Exception as e:
            self.logger.error(f"Error creating target: {e}")
            return None
    
    def create_task_ospd(self, target_id):
        """Create a task in OpenVAS using OSP protocol."""
        try:
            import xml.etree.ElementTree as ET
            
            # Create task XML
            task_xml = f"""
            <create_task>
                <name>AI_MAL_Scan_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}</name>
                <target_id>{target_id}</target_id>
                <config>
                    <scanner>
                        <name>{self.scan_config}</name>
                    </scanner>
                </config>
            </create_task>
            """
            
            # Send request using OSP protocol
            result = subprocess.run(
                ["gvm-cli", "--protocol", "OSP", "socket", "--sockpath", "/run/ospd/ospd.sock", "--xml", task_xml],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            if result.returncode == 0:
                root = ET.fromstring(result.stdout.decode())
                return root.get('id')
            return None
        except Exception as e:
            self.logger.error(f"Error creating task: {e}")
            return None
    
    def start_task_ospd(self, task_id):
        """Start a task in OpenVAS using OSP protocol."""
        try:
            import xml.etree.ElementTree as ET
            
            # Create start task XML
            start_task_xml = f"""
            <start_task>
                <task_id>{task_id}</task_id>
            </start_task>
            """
            
            # Send request using OSP protocol
            result = subprocess.run(
                ["gvm-cli", "--protocol", "OSP", "socket", "--sockpath", "/run/ospd/ospd.sock", "--xml", start_task_xml],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            if result.returncode == 0:
                return True
            return False
        except Exception as e:
            self.logger.error(f"Error starting task: {e}")
            return False
    
    def get_task_status_ospd(self, task_id):
        """Get the status of a task in OpenVAS using OSP protocol."""
        try:
            import xml.etree.ElementTree as ET
            
            # Create get status XML
            status_xml = f"""
            <get_tasks task_id="{task_id}"/>
            """
            
            # Send request using OSP protocol
            result = subprocess.run(
                ["gvm-cli", "--protocol", "OSP", "socket", "--sockpath", "/run/ospd/ospd.sock", "--xml", status_xml],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            if result.returncode == 0:
                root = ET.fromstring(result.stdout.decode())
                status = root.find('.//status')
                if status is not None:
                    return status.text
            return None
        except Exception as e:
            self.logger.error(f"Error getting task status: {e}")
            return None
    
    def get_scan_results_ospd(self, task_id):
        """Get the scan results of a task in OpenVAS using OSP protocol."""
        try:
            import xml.etree.ElementTree as ET
            
            # Create get results XML
            results_xml = f"""
            <get_results task_id="{task_id}"/>
            """
            
            # Send request using OSP protocol
            result = subprocess.run(
                ["gvm-cli", "--protocol", "OSP", "socket", "--sockpath", "/run/ospd/ospd.sock", "--xml", results_xml],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            if result.returncode == 0:
                root = ET.fromstring(result.stdout.decode())
                results = []
                for result in root.findall('.//result'):
                    results.append({
                        'host': result.get('host'),
                        'port': result.get('port'),
                        'service': result.get('service'),
                        'name': result.get('name'),
                        'severity': result.get('severity'),
                        'cvss': result.get('cvss')
                    })
                return results
            return None
        except Exception as e:
            self.logger.error(f"Error getting scan results: {e}")
            return None 