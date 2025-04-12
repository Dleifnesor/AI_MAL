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
import re

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
        """Check if OpenVAS is available and running."""
        self.logger.info("Checking if OpenVAS is available")
        console.print("[*] Checking if OpenVAS is available...")
        
        # Check if environment variable for password is set
        self.gvm_password = os.environ.get('GVM_PASSWORD')
        if self.gvm_password:
            self.logger.info("Found GVM_PASSWORD in environment")
            console.print("[green]Found GVM_PASSWORD in environment[/green]")
        
        # Check for socket file in standard locations based on INSTALL.md
        socket_paths = [
            "/run/redis-openvas/redis.sock",  # Redis socket
            "/run/ospd/ospd.sock",            # OSPD socket
            "/var/run/ospd/ospd.sock"         # Alternative OSPD socket
        ]
        
        socket_found = False
        for path in socket_paths:
            if os.path.exists(path):
                self.logger.info(f"Found socket at {path}")
                console.print(f"[green]Found socket at {path}[/green]")
                if "redis" in path:
                    self.redis_socket = path
                else:
                    self.ospd_socket = path
                    socket_found = True
        
        if not hasattr(self, 'ospd_socket'):
            self.logger.warning("OSPD socket not found in standard locations")
            console.print("[yellow]OSPD socket not found in standard locations[/yellow]")
            
            # Try to get socket path from service config
            try:
                service_output = subprocess.run(
                    ["systemctl", "show", "ospd-openvas", "--property=ExecStart"],
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                ).stdout.strip()
                
                socket_match = re.search(r'--socket-path[= ]([^ ]+)', service_output)
                if socket_match:
                    path = socket_match.group(1)
                    if os.path.exists(path):
                        self.ospd_socket = path
                        socket_found = True
                        self.logger.info(f"Found OSPD socket from service config: {path}")
                        console.print(f"[green]Found OSPD socket from service config: {path}[/green]")
                    else:
                        self.logger.warning(f"OSPD socket path from config {path} doesn't exist")
                        console.print(f"[yellow]OSPD socket from config {path} doesn't exist[/yellow]")
            except Exception as e:
                self.logger.error(f"Error getting OSPD socket path from service config: {str(e)}")
        
        # Check if services are running
        services_status = {}
        for service in ["ospd-openvas", "gvmd", "redis-server@openvas"]:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service],
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
                status = result.stdout.strip()
                services_status[service] = status
                if status != "active":
                    self.logger.warning(f"Service {service} is not active (status: {status})")
                    console.print(f"[yellow]Service {service} is not active (status: {status})[/yellow]")
                else:
                    console.print(f"[green]Service {service} is active[/green]")
            except Exception as e:
                self.logger.error(f"Error checking service {service}: {str(e)}")
                services_status[service] = "unknown"
        
        # Check if Redis is properly set up
        redis_ok = False
        if hasattr(self, 'redis_socket') and os.path.exists(self.redis_socket):
            try:
                # Check if Redis has NVTs loaded
                import redis
                r = redis.Redis(unix_socket_path=self.redis_socket)
                if r.ping():
                    redis_ok = True
                    self.logger.info("Redis connection successful")
                    console.print("[green]Redis connection successful[/green]")
                else:
                    self.logger.warning("Redis ping failed")
                    console.print("[yellow]Redis ping failed[/yellow]")
            except Exception as e:
                self.logger.error(f"Error connecting to Redis: {str(e)}")
                console.print(f"[red]Error connecting to Redis: {str(e)}[/red]")
        
        # If socket not found or services not running, give guidance
        if not socket_found:
            self.logger.warning("OpenVAS is not properly configured")
            console.print("[yellow]OpenVAS is not properly configured[/yellow]")
            console.print("[blue]Try the following steps:[/blue]")
            console.print("1. Install OpenVAS: sudo apt-get install openvas")
            console.print("2. Run setup: sudo gvm-setup")
            console.print("3. Start services: sudo gvm-start")
            console.print("4. Check status: sudo gvm-check-setup")
            return False
        
        # Try to connect to OSPD using XML
        try:
            self.logger.info(f"Testing connection to OSPD at {self.ospd_socket}")
            console.print(f"[blue]Testing connection to OSPD at {self.ospd_socket}[/blue]")
            
            # First try with password from environment
            if hasattr(self, 'gvm_password') and self.gvm_password:
                try:
                    result = subprocess.run(
                        ["gvm-cli", "--protocol", "OSP", "socket", "--socketpath", self.ospd_socket, 
                         "--xml", "<get_version/>"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0 and "<version>" in result.stdout:
                        version_match = re.search(r"<version>([^<]+)</version>", result.stdout)
                        if version_match:
                            version = version_match.group(1)
                            self.logger.info(f"Successfully connected to OpenVAS version {version}")
                            console.print(f"[green]Successfully connected to OpenVAS version {version}[/green]")
                            return True
                except Exception as e:
                    self.logger.error(f"Error connecting to OSPD with environment password: {str(e)}")
            
            # Try without credentials
            result = subprocess.run(
                ["gvm-cli", "--protocol", "OSP", "socket", "--socketpath", self.ospd_socket, 
                 "--xml", "<get_version/>"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and "<version>" in result.stdout:
                version_match = re.search(r"<version>([^<]+)</version>", result.stdout)
                if version_match:
                    version = version_match.group(1)
                    self.logger.info(f"Successfully connected to OpenVAS version {version}")
                    console.print(f"[green]Successfully connected to OpenVAS version {version}[/green]")
                    return True
            
            # If connection failed, try to extract password from error message
            if "password" in result.stderr.lower() or "authentication" in result.stderr.lower():
                self.logger.warning("OpenVAS requires authentication")
                console.print("[yellow]OpenVAS requires authentication[/yellow]")
                
                # Try to find password in the logs
                try:
                    log_file = "/var/log/gvm/gvm-setup.log"
                    if os.path.exists(log_file):
                        with open(log_file, 'r') as f:
                            log_content = f.read()
                        password_match = re.search(r"User created with password '([^']+)'", log_content)
                        if password_match:
                            self.gvm_password = password_match.group(1)
                            self.logger.info("Found GVM password in setup logs")
                            console.print("[green]Found GVM password in setup logs[/green]")
                            
                            # Try again with extracted password
                            try:
                                result = subprocess.run(
                                    ["gvm-cli", "--protocol", "OSP", "socket", "--socketpath", self.ospd_socket, 
                                     "--xml", "<get_version/>"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True,
                                    timeout=10
                                )
                                
                                if result.returncode == 0 and "<version>" in result.stdout:
                                    version_match = re.search(r"<version>([^<]+)</version>", result.stdout)
                                    if version_match:
                                        version = version_match.group(1)
                                        self.logger.info(f"Successfully connected to OpenVAS version {version}")
                                        console.print(f"[green]Successfully connected to OpenVAS version {version}[/green]")
                                        return True
                            except Exception as e:
                                self.logger.error(f"Error connecting to OSPD with extracted password: {str(e)}")
                except Exception as e:
                    self.logger.error(f"Error trying to extract password from logs: {str(e)}")
            
            self.logger.warning(f"Connection test to OSPD failed. Output: {result.stdout}, Error: {result.stderr}")
            console.print("[yellow]Connection test to OSPD failed[/yellow]")
            console.print("[blue]Try running:[/blue]")
            console.print("1. sudo gvm-check-setup to verify installation")
            console.print("2. sudo gvm-setup to initialize OpenVAS")
            console.print("3. sudo gvm-start to start all services")
            console.print("4. Check if GVM_PASSWORD environment variable is set")
            return False
            
        except Exception as e:
            self.logger.error(f"Error testing OpenVAS connection: {str(e)}")
            console.print(f"[red]Error testing OpenVAS connection: {str(e)}[/red]")
            return False

    def connect_to_openvas(self):
        """Connect to OpenVAS using the OSP protocol"""
        if not self.is_openvas_available():
            self.logger.error("OpenVAS is not available, cannot connect")
            console.print("[red]OpenVAS is not available, cannot connect[/red]")
            console.print("[yellow]Please ensure OpenVAS is installed and running.[/yellow]")
            console.print("[blue]Run 'sudo gvm-start' to start the services if needed.[/blue]")
            return False
        
        try:
            self.logger.info("Attempting to connect to OpenVAS using OSP protocol")
            console.print("[*] Connecting to OpenVAS...")
            
            # Build connection command based on available credentials
            command = ["gvm-cli", "--protocol", "OSP", "socket", "--socketpath", self.ospd_socket]
            
            # If we have a password, try to use it
            if hasattr(self, 'gvm_password') and self.gvm_password:
                # For now with OSP we don't use the password directly,
                # the socket connection doesn't require auth for basic operations
                pass
                
            # Test connection with version command
            test_cmd = command + ["--xml", "<get_version/>"]
            self.logger.debug(f"Testing connection with command: {' '.join(test_cmd)}")
            
            result = subprocess.run(
                test_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and "<version>" in result.stdout:
                version_match = re.search(r"<version>([^<]+)</version>", result.stdout)
                if version_match:
                    self.openvas_version = version_match.group(1)
                    self.logger.info(f"Successfully connected to OpenVAS version {self.openvas_version}")
                    console.print(f"[green]Successfully connected to OpenVAS version {self.openvas_version}[/green]")
                    self.openvas_connected = True
                    return True
            
            self.logger.error(f"Failed to connect to OpenVAS. Output: {result.stdout}, Error: {result.stderr}")
            console.print("[red]Failed to connect to OpenVAS[/red]")
            
            if "permission denied" in result.stderr.lower():
                console.print("[yellow]Socket permission issue detected[/yellow]")
                console.print(f"[blue]Try running: sudo chmod 666 {self.ospd_socket}[/blue]")
            
            if "Connection refused" in result.stderr:
                console.print("[yellow]Connection refused - OpenVAS service may not be running[/yellow]")
                console.print("[blue]Try running: sudo gvm-start[/blue]")
            
            return False
            
        except subprocess.TimeoutExpired:
            self.logger.error("Connection to OpenVAS timed out")
            console.print("[red]Connection to OpenVAS timed out[/red]")
            console.print("[yellow]The service may be starting up or overloaded[/yellow]")
            return False
            
        except Exception as e:
            self.logger.error(f"Error connecting to OpenVAS: {str(e)}")
            console.print(f"[red]Error connecting to OpenVAS: {str(e)}[/red]")
            return False

    def display_scan_results(self, results):
        """Display scan results in a Rich formatted output."""
        try:
            from rich.panel import Panel
            from rich.table import Table
            from rich.console import Console
            from rich.box import DOUBLE_EDGE
            
            if not results or len(results) == 0:
                console.print(Panel("[bold yellow]No hosts discovered[/bold yellow]", 
                                   title="Scan Results", 
                                   border_style="yellow",
                                   box=DOUBLE_EDGE))
                return
            
            # Create summary table of discovered hosts
            hosts_table = Table(title="Discovered Hosts", box=DOUBLE_EDGE, show_header=True, header_style="bold cyan")
            hosts_table.add_column("IP Address", style="green")
            hosts_table.add_column("Hostname", style="blue")
            hosts_table.add_column("OS", style="magenta")
            hosts_table.add_column("Open Ports", style="yellow")
            
            # Process and display each host
            unique_hosts = {}
            for host in results:
                ip = host.get('ip', 'Unknown')
                if ip not in unique_hosts:
                    unique_hosts[ip] = {
                        'hostname': host.get('hostname', 'Unknown'),
                        'os': host.get('os', 'Unknown'),
                        'ports': []
                    }
                port = host.get('port')
                if port:
                    unique_hosts[ip]['ports'].append(port)
            
            # Add hosts to table
            for ip, host_info in unique_hosts.items():
                ports_str = ", ".join(sorted(host_info['ports'])) if host_info['ports'] else "None detected"
                hosts_table.add_row(
                    ip,
                    host_info['hostname'],
                    host_info['os'],
                    ports_str
                )
            
            # Create panel to contain the table
            host_panel = Panel(
                hosts_table,
                title="[bold green]Network Host Discovery Results[/bold green]",
                border_style="green",
                box=DOUBLE_EDGE
            )
            
            console.print(host_panel)
            
        except Exception as e:
            self.logger.error(f"Error displaying scan results: {str(e)}")
            console.print(f"[red]Error displaying scan results: {str(e)}[/red]")
            
            # Fallback to simple text display
            console.print("\n[bold]Discovered Hosts:[/bold]")
            for host in results:
                console.print(f"  IP: {host.get('ip', 'Unknown')}, Hostname: {host.get('hostname', 'Unknown')}")
                if 'port' in host and host['port']:
                    console.print(f"    Port: {host['port']}")

    def display_vulnerabilities(self, vulnerabilities):
        """Display vulnerabilities in a Rich formatted output."""
        try:
            from rich.panel import Panel
            from rich.table import Table
            from rich.console import Console
            from rich.box import DOUBLE_EDGE
            from rich.text import Text
            
            if not vulnerabilities or len(vulnerabilities) == 0:
                console.print(Panel("[bold yellow]No vulnerabilities found[/bold yellow]", 
                                   title="Vulnerability Scan Results", 
                                   border_style="yellow",
                                   box=DOUBLE_EDGE))
                return
            
            # Create a table for vulnerabilities
            vuln_table = Table(title="Detected Vulnerabilities", box=DOUBLE_EDGE, show_header=True, header_style="bold red")
            vuln_table.add_column("Host", style="cyan")
            vuln_table.add_column("Port", style="blue")
            vuln_table.add_column("Service", style="green")
            vuln_table.add_column("Vulnerability", style="yellow")
            vuln_table.add_column("Severity", style="red")
            
            # Add each vulnerability to the table
            for vuln in vulnerabilities:
                # Set severity color based on value
                severity = vuln.get('severity', '0.0')
                try:
                    severity_float = float(severity)
                    if severity_float >= 9.0:
                        severity_text = Text(severity, style="bold red")
                    elif severity_float >= 7.0:
                        severity_text = Text(severity, style="red")
                    elif severity_float >= 4.0:
                        severity_text = Text(severity, style="yellow")
                    else:
                        severity_text = Text(severity, style="green")
                except:
                    severity_text = Text(severity, style="yellow")
                
                # Add the row
                vuln_table.add_row(
                    vuln.get('host', 'Unknown'),
                    vuln.get('port', 'Unknown'),
                    vuln.get('service', 'Unknown'),
                    vuln.get('name', 'Unknown'),
                    severity_text
                )
            
            # Create panel to contain the table
            vuln_panel = Panel(
                vuln_table,
                title="[bold red]Vulnerability Scan Results[/bold red]",
                border_style="red",
                box=DOUBLE_EDGE
            )
            
            console.print(vuln_panel)
            
            # Display additional vulnerability details in separate panels
            if any('description' in v for v in vulnerabilities):
                console.print("\n[bold]Vulnerability Details:[/bold]")
                for i, vuln in enumerate(vulnerabilities):
                    if 'description' in vuln and vuln['description']:
                        description = vuln['description']
                        # Truncate long descriptions
                        if len(description) > 500:
                            description = description[:500] + "..."
                        
                        detail_panel = Panel(
                            description,
                            title=f"[bold yellow]{vuln.get('name', 'Unknown')}[/bold yellow] - Host: {vuln.get('host', 'Unknown')}",
                            border_style="yellow"
                        )
                        console.print(detail_panel)
            
        except Exception as e:
            self.logger.error(f"Error displaying vulnerabilities: {str(e)}")
            console.print(f"[red]Error displaying vulnerabilities: {str(e)}[/red]")
            
            # Fallback to simple text display
            console.print("\n[bold]Detected Vulnerabilities:[/bold]")
            for vuln in vulnerabilities:
                console.print(f"  Host: {vuln.get('host', 'Unknown')}, Port: {vuln.get('port', 'Unknown')}")
                console.print(f"  Vulnerability: {vuln.get('name', 'Unknown')}, Severity: {vuln.get('severity', 'Unknown')}")

    def scan_with_openvas(self, target, ports=None):
        """
        Scan targets with OpenVAS.
        
        Args:
            target (str): The target to scan
            ports (str, optional): The ports to scan. Defaults to None.
        
        Returns:
            dict: The scan results
        """
        self.logger.info(f"Scanning {target} with OpenVAS")
        
        # Create a rich Panel for the scan header
        from rich.panel import Panel
        from rich.text import Text
        
        header_text = Text.from_markup(f"[bold]OpenVAS Vulnerability Scan[/bold]\nTarget: [cyan]{target}[/cyan]")
        if ports:
            header_text.append(f"\nPorts: [yellow]{ports}[/yellow]")
        
        console.print(Panel(
            header_text,
            title="[bold blue]AI_MAL Vulnerability Scanner[/bold blue]",
            border_style="blue"
        ))
        
        # Connect to OpenVAS
        if not self.connect_to_openvas():
            self.logger.error("Failed to connect to OpenVAS")
            console.print(Panel("[bold red]Failed to connect to OpenVAS. Scan aborted.[/bold red]", 
                              border_style="red"))
            return {}
        
        try:
            # Progress tracking
            from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn, SpinnerColumn
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                # Create target
                target_task = progress.add_task("[cyan]Creating target...", total=None)
                target_id = self.create_target_ospd(target)
                if not target_id:
                    progress.update(target_task, description="[red]Failed to create target!")
                    return {}
                
                progress.update(target_task, description="[green]Target created successfully", completed=True)
                
                # Create task
                task_task = progress.add_task("[cyan]Creating scan task...", total=None)
                task_id = self.create_task_ospd(target, target_id)
                if not task_id:
                    progress.update(task_task, description="[red]Failed to create scan task!")
                    return {}
                
                progress.update(task_task, description="[green]Scan task created successfully", completed=True)
                
                # Start task
                start_task = progress.add_task("[cyan]Starting scan...", total=None)
                if not self.start_task_ospd(task_id):
                    progress.update(start_task, description="[red]Failed to start scan!")
                    return {}
                
                progress.update(start_task, description="[green]Scan started successfully", completed=True)
                
                # Wait for task to complete
                scan_task = progress.add_task("[cyan]Scanning...", total=100)
                
                status = "Running"
                last_progress = 0
                while status == "Running" or status == "Requested":
                    time.sleep(10)  # Check every 10 seconds
                    status, progress_value = self.get_task_status_ospd(task_id)
                    
                    # Only update if progress has changed
                    if progress_value > last_progress:
                        progress.update(scan_task, completed=progress_value)
                        last_progress = progress_value
                    
                    if status == "Stopped" or status == "Failed":
                        progress.update(scan_task, description=f"[red]Scan failed: {status}")
                        return {}
                
                progress.update(scan_task, description="[green]Scan completed!", completed=100)
                
                # Get results
                results_task = progress.add_task("[cyan]Retrieving results...", total=None)
                results = self.get_scan_results_ospd(task_id)
                
                if results:
                    progress.update(results_task, description=f"[green]Found {len(results)} vulnerabilities", completed=True)
                else:
                    progress.update(results_task, description="[yellow]No vulnerabilities found", completed=True)
            
            # Display results
            if results:
                self.display_vulnerabilities(results)
                return results
            else:
                console.print(Panel("[bold yellow]No vulnerabilities were detected[/bold yellow]", 
                                 title="Scan Results", 
                                 border_style="yellow"))
                return {}
                
        except Exception as e:
            self.logger.error(f"Error during OpenVAS scan: {str(e)}")
            console.print(Panel(f"[bold red]OpenVAS scan failed:[/bold red]\n{str(e)}", 
                              border_style="red"))
            return {}
    
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
            return self.scan_with_openvas(self.target)
    
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
    
    def create_target_ospd(self, target_ip, ports=None):
        """Create a target in OpenVAS using OSP protocol."""
        if not hasattr(self, 'ospd_socket'):
            self.is_openvas_available()
        
        target_name = f"AI_MAL_Target_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.logger.info(f"Creating target '{target_name}' for {target_ip}")
        console.print(f"[blue]Creating target '{target_name}' for {target_ip}[/blue]")
        
        # Build XML command for create_target
        xml_data = f"""
        <create_target>
            <name>{target_name}</name>
            <hosts>{target_ip}</hosts>
            <comment>Created by AI_MAL at {datetime.now().isoformat()}</comment>
        </create_target>
        """
        
        try:
            # Send request to OpenVAS
            result = subprocess.run(
                ["gvm-cli", "--protocol", "OSP", "socket", "--socketpath", self.ospd_socket, "--xml", xml_data],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse the response to get target ID
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                target_id = root.attrib.get('id')
                
                if target_id:
                    self.logger.info(f"Successfully created target with ID: {target_id}")
                    console.print(f"[green]Successfully created target with ID: {target_id}[/green]")
                    return target_id
                else:
                    self.logger.warning(f"Created target but couldn't get ID: {result.stdout}")
                    console.print(f"[yellow]Created target but couldn't get ID[/yellow]")
                    return None
            else:
                self.logger.error(f"Failed to create target: {result.stderr}")
                console.print(f"[red]Failed to create target: {result.stderr}[/red]")
                return None
        except Exception as e:
            self.logger.error(f"Error creating target: {str(e)}")
            console.print(f"[red]Error creating target: {str(e)}[/red]")
            return None
    
    def create_task_ospd(self, target_ip, target_id):
        """Create a scan task in OpenVAS using OSP protocol."""
        if not hasattr(self, 'ospd_socket'):
            self.is_openvas_available()
        
        task_name = f"AI_MAL_Scan_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.logger.info(f"Creating scan task '{task_name}' for target ID {target_id}")
        console.print(f"[blue]Creating scan task '{task_name}' for target {target_ip}[/blue]")
        
        # Build XML command for create_task
        xml_data = f"""
        <create_task>
            <name>{task_name}</name>
            <target id="{target_id}"/>
            <scanner>
                <name>OpenVAS Default</name>
                <type>2</type>
            </scanner>
            <config>
                <id>daba56c8-73ec-11df-a475-002264764cea</id>
            </config>
        </create_task>
        """
        
        try:
            # Send request to OpenVAS
            result = subprocess.run(
                ["gvm-cli", "--protocol", "OSP", "socket", "--socketpath", self.ospd_socket, "--xml", xml_data],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse the response to get task ID
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                task_id = root.attrib.get('id')
                
                if task_id:
                    self.logger.info(f"Successfully created task with ID: {task_id}")
                    console.print(f"[green]Successfully created task with ID: {task_id}[/green]")
                    return task_id
                else:
                    self.logger.warning(f"Created task but couldn't get ID: {result.stdout}")
                    console.print(f"[yellow]Created task but couldn't get ID[/yellow]")
                    return None
            else:
                self.logger.error(f"Failed to create task: {result.stderr}")
                console.print(f"[red]Failed to create task: {result.stderr}[/red]")
                return None
        except Exception as e:
            self.logger.error(f"Error creating task: {str(e)}")
            console.print(f"[red]Error creating task: {str(e)}[/red]")
            return None
    
    def start_task_ospd(self, task_id):
        """Start a scan task in OpenVAS using OSP protocol."""
        if not hasattr(self, 'ospd_socket'):
            self.is_openvas_available()
        
        self.logger.info(f"Starting scan task {task_id}")
        console.print(f"[blue]Starting scan task {task_id}[/blue]")
        
        # Build XML command to start task
        xml_data = f"""
        <start_task task_id="{task_id}"/>
        """
        
        try:
            # Send request to OpenVAS
            result = subprocess.run(
                ["gvm-cli", "--protocol", "OSP", "socket", "--socketpath", self.ospd_socket, "--xml", xml_data],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self.logger.info(f"Successfully started task {task_id}")
                console.print(f"[green]Successfully started task {task_id}[/green]")
                return True
            else:
                self.logger.error(f"Failed to start task: {result.stderr}")
                console.print(f"[red]Failed to start task: {result.stderr}[/red]")
                return False
        except Exception as e:
            self.logger.error(f"Error starting task: {str(e)}")
            console.print(f"[red]Error starting task: {str(e)}[/red]")
            return False
    
    def get_task_status_ospd(self, task_id):
        """Get the status of a scan task in OpenVAS using OSP protocol."""
        if not hasattr(self, 'ospd_socket'):
            self.is_openvas_available()
        
        # Build XML command to get task status
        xml_data = f"""
        <get_tasks task_id="{task_id}"/>
        """
        
        try:
            # Send request to OpenVAS
            result = subprocess.run(
                ["gvm-cli", "--protocol", "OSP", "socket", "--socketpath", self.ospd_socket, "--xml", xml_data],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse the response to get task status and progress
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                status_elem = root.find(".//status")
                progress_elem = root.find(".//progress")
                
                status = "Unknown"
                progress = 0
                
                if status_elem is not None:
                    status = status_elem.text
                
                if progress_elem is not None:
                    try:
                        progress = int(float(progress_elem.text))
                    except ValueError:
                        progress = 0
                
                self.logger.info(f"Task {task_id} status: {status}, progress: {progress}%")
                return status, progress
            else:
                self.logger.error(f"Failed to get task status: {result.stderr}")
                return "Failed", 0
        except Exception as e:
            self.logger.error(f"Error getting task status: {str(e)}")
            return "Error", 0
    
    def get_scan_results_ospd(self, task_id):
        """Get the results of a scan task in OpenVAS using OSP protocol."""
        if not hasattr(self, 'ospd_socket'):
            self.is_openvas_available()
        
        self.logger.info(f"Getting results for task {task_id}")
        console.print(f"[blue]Getting results for task {task_id}[/blue]")
        
        # Build XML command to get results
        xml_data = f"""
        <get_results task_id="{task_id}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"/>
        """
        
        try:
            # Send request to OpenVAS
            result = subprocess.run(
                ["gvm-cli", "--protocol", "OSP", "socket", "--socketpath", self.ospd_socket, "--xml", xml_data],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Parse the response to get results
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                result_elements = root.findall(".//result")
                
                results = []
                for result_elem in result_elements:
                    # Extract vulnerability details
                    host = result_elem.find("host")
                    port = result_elem.find("port")
                    name = result_elem.find("name")
                    severity = result_elem.find("severity")
                    description = result_elem.find("description")
                    
                    # Add to results if it's a real vulnerability
                    if (severity is not None and float(severity.text) > 0 and 
                        name is not None and host is not None):
                        
                        results.append({
                            "host": host.text if host is not None else "Unknown",
                            "port": port.text if port is not None else "Unknown",
                            "name": name.text if name is not None else "Unknown",
                            "severity": severity.text if severity is not None else "0.0",
                            "description": description.text if description is not None else "",
                            "service": "Unknown"  # Parse from port if needed
                        })
                
                self.logger.info(f"Found {len(results)} vulnerabilities")
                console.print(f"[green]Found {len(results)} vulnerabilities[/green]")
                return results
            else:
                self.logger.error(f"Failed to get results: {result.stderr}")
                console.print(f"[red]Failed to get results: {result.stderr}[/red]")
                return []
        except Exception as e:
            self.logger.error(f"Error getting results: {str(e)}")
            console.print(f"[red]Error getting results: {str(e)}[/red]")
            return [] 