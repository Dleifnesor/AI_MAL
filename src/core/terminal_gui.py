#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL Terminal GUI Module
========================

This module handles the terminal-based GUI for the AI_MAL tool.
"""

import os
import sys
import time
import platform
import shutil
from datetime import datetime
from .logger import LoggerWrapper

# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    
    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"
    
    @staticmethod
    def disable():
        """Disable all color codes"""
        Colors.RESET = ""
        Colors.BOLD = ""
        Colors.UNDERLINE = ""
        Colors.BLACK = ""
        Colors.RED = ""
        Colors.GREEN = ""
        Colors.YELLOW = ""
        Colors.BLUE = ""
        Colors.MAGENTA = ""
        Colors.CYAN = ""
        Colors.WHITE = ""
        Colors.BG_BLACK = ""
        Colors.BG_RED = ""
        Colors.BG_GREEN = ""
        Colors.BG_YELLOW = ""
        Colors.BG_BLUE = ""
        Colors.BG_MAGENTA = ""
        Colors.BG_CYAN = ""
        Colors.BG_WHITE = ""

class TerminalGUI:
    """
    TerminalGUI class for displaying information in the terminal.
    """
    
    def __init__(self, quiet=False, disable_colors=False):
        """
        Initialize the terminal GUI.
        
        Args:
            quiet (bool): If True, suppress non-essential output
            disable_colors (bool): If True, disable color output
        """
        self.quiet = quiet
        self.logger = LoggerWrapper("TerminalGUI")
        
        # Get terminal size
        self.term_width, self.term_height = self._get_terminal_size()
        
        # Disable colors if requested or if on Windows without ANSI support
        if disable_colors or (platform.system() == "Windows" and not self._has_ansi_support()):
            Colors.disable()
        
        # Initialize progress tracking
        self.progress = {
            "scanning": {"status": "pending", "progress": 0},
            "vulnerability_scanning": {"status": "pending", "progress": 0},
            "exploitation": {"status": "pending", "progress": 0},
            "script_generation": {"status": "pending", "progress": 0},
            "ai_analysis": {"status": "pending", "progress": 0}
        }
        
        # ASCII art logo
        self.logo = r"""
    _   ___ __  __    _    _     
   /_\ |_ _|  \/  |  /_\  | |    
  / _ \ | || |\/| | / _ \ | |__  
 /_/ \_\___|_|  |_|/_/ \_\|____|
                                
 AI-Powered Penetration Testing
"""
    
    def _get_terminal_size(self):
        """
        Get the terminal size.
        
        Returns:
            tuple: (width, height) of the terminal
        """
        try:
            columns, lines = shutil.get_terminal_size()
            return columns, lines
        except Exception:
            # Default size if can't determine
            return 80, 24
    
    def _has_ansi_support(self):
        """
        Check if the terminal supports ANSI color codes.
        
        Returns:
            bool: True if ANSI is supported, False otherwise
        """
        # Check if running in a terminal that supports colors
        if not sys.stdout.isatty():
            return False
        
        # Check if TERM environment variable indicates color support
        term = os.environ.get("TERM", "")
        if term in ["xterm", "xterm-color", "xterm-256color", "linux", "screen", "screen-256color"]:
            return True
        
        # On Windows, check if ANSICON or WT_SESSION is set
        if platform.system() == "Windows":
            if os.environ.get("ANSICON") or os.environ.get("WT_SESSION"):
                return True
        
        return False
    
    def show_header(self):
        """
        Show the tool header.
        """
        if self.quiet:
            return
        
        # Display logo and header
        print(f"{Colors.CYAN}{self.logo}{Colors.RESET}")
        print(f"{Colors.BOLD}Version: 1.0.0{Colors.RESET}")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * self.term_width)
        print()
    
    def show_footer(self):
        """
        Show the tool footer.
        """
        if self.quiet:
            return
        
        print()
        print("=" * self.term_width)
        print(f"{Colors.GREEN}AI_MAL completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    
    def update_progress(self, component, status, progress=None, message=None):
        """
        Update the progress status of a component.
        
        Args:
            component (str): Component name
            status (str): Status (pending/running/complete/error)
            progress (int, optional): Progress percentage (0-100)
            message (str, optional): Status message
        """
        if component not in self.progress:
            return
        
        self.progress[component]["status"] = status
        
        if progress is not None:
            self.progress[component]["progress"] = progress
        
        if message:
            self.progress[component]["message"] = message
        
        # Show progress if not in quiet mode
        if not self.quiet:
            self.show_progress()
    
    def show_progress(self):
        """
        Show the current progress status.
        """
        if self.quiet:
            return
        
        # Clear the terminal
        print("\033[H\033[J", end="")
        
        # Show header
        print(f"{Colors.CYAN}{self.logo}{Colors.RESET}")
        print(f"{Colors.BOLD}Status:{Colors.RESET}")
        
        # Show component status
        for component, data in self.progress.items():
            # Format component name
            component_name = component.replace("_", " ").title()
            
            # Choose color based on status
            if data["status"] == "pending":
                color = Colors.YELLOW
            elif data["status"] == "running":
                color = Colors.BLUE
            elif data["status"] == "complete":
                color = Colors.GREEN
            elif data["status"] == "error":
                color = Colors.RED
            else:
                color = Colors.RESET
            
            # Show status and progress bar if running
            status_text = data["status"].upper()
            
            if data["status"] == "running" and "progress" in data:
                # Create progress bar
                progress = data["progress"]
                bar_width = 20
                filled_width = int(bar_width * progress / 100)
                bar = "█" * filled_width + "░" * (bar_width - filled_width)
                
                print(f"  {component_name}: {color}{status_text}{Colors.RESET} [{bar}] {progress}%")
            else:
                print(f"  {component_name}: {color}{status_text}{Colors.RESET}")
            
            # Show message if available
            if "message" in data:
                print(f"    {data['message']}")
        
        print()
    
    def spinner(self, message, duration=5):
        """
        Show a spinner with a message for a specified duration.
        
        Args:
            message (str): Message to display
            duration (int): Duration in seconds
        """
        if self.quiet:
            return
        
        spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        end_time = time.time() + duration
        
        i = 0
        try:
            while time.time() < end_time:
                char = spinner_chars[i % len(spinner_chars)]
                sys.stdout.write(f"\r{char} {message}")
                sys.stdout.flush()
                time.sleep(0.1)
                i += 1
            
            sys.stdout.write(f"\r✓ {message}\n")
            sys.stdout.flush()
        except KeyboardInterrupt:
            sys.stdout.write(f"\r  {message}\n")
            sys.stdout.flush()
    
    def display_scan_results(self, scan_results):
        """
        Display scan results in a user-friendly format.
        
        Args:
            scan_results (dict): Scan results to display
        """
        if self.quiet:
            return
        
        print()
        print(f"{Colors.BOLD}{Colors.UNDERLINE}Scan Results:{Colors.RESET}")
        
        # Display hosts info
        if "hosts" in scan_results:
            print(f"\n{Colors.BOLD}Hosts:{Colors.RESET}")
            
            for host in scan_results["hosts"]:
                # Get the host IP and status
                host_ip = next((addr["addr"] for addr in host.get("addresses", []) if addr.get("addrtype") == "ipv4"), "Unknown")
                status = host.get("status", "Unknown")
                
                # Display host info
                print(f"  {Colors.GREEN}{host_ip}{Colors.RESET} - Status: {status}")
                
                # Display hostnames if available
                hostnames = host.get("hostnames", [])
                if hostnames:
                    hostname_list = ", ".join([h.get("name", "") for h in hostnames if h.get("name")])
                    if hostname_list:
                        print(f"    Hostnames: {hostname_list}")
                
                # Display OS info if available
                os_info = host.get("os", [])
                if os_info:
                    os_name = os_info[0].get("name", "Unknown") if os_info else "Unknown"
                    os_accuracy = os_info[0].get("accuracy", "Unknown") if os_info else "Unknown"
                    print(f"    OS: {os_name} (Accuracy: {os_accuracy})")
                
                # Display open ports
                open_ports = [port for port in host.get("ports", []) if port.get("state") == "open"]
                if open_ports:
                    print(f"    Open Ports:")
                    for port in open_ports:
                        port_id = port.get("portid", "")
                        protocol = port.get("protocol", "")
                        service = port.get("service", {})
                        service_name = service.get("name", "")
                        product = service.get("product", "")
                        version = service.get("version", "")
                        
                        service_info = ""
                        if service_name:
                            service_info += service_name
                        if product:
                            service_info += f" ({product}"
                            if version:
                                service_info += f" {version}"
                            service_info += ")"
                        
                        print(f"      {Colors.YELLOW}{port_id}/{protocol}{Colors.RESET} - {service_info}")
                
                print()  # Add space between hosts
        
        # Display vulnerabilities if available
        if "vulnerabilities" in scan_results:
            vulnerabilities = scan_results["vulnerabilities"]
            
            print(f"\n{Colors.BOLD}Vulnerabilities ({len(vulnerabilities)}):{Colors.RESET}")
            
            # Group vulnerabilities by severity
            severity_groups = {
                "Critical": [],
                "High": [],
                "Medium": [],
                "Low": [],
                "Unknown": []
            }
            
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "Unknown")
                
                # Normalize severity
                if isinstance(severity, (int, float)) or (isinstance(severity, str) and severity.replace('.', '', 1).isdigit()):
                    severity_val = float(severity)
                    if severity_val >= 9.0:
                        group = "Critical"
                    elif severity_val >= 7.0:
                        group = "High"
                    elif severity_val >= 4.0:
                        group = "Medium"
                    else:
                        group = "Low"
                else:
                    severity_lower = str(severity).lower()
                    if "critical" in severity_lower:
                        group = "Critical"
                    elif "high" in severity_lower:
                        group = "High"
                    elif "medium" in severity_lower or "moderate" in severity_lower:
                        group = "Medium"
                    elif "low" in severity_lower:
                        group = "Low"
                    else:
                        group = "Unknown"
                
                severity_groups[group].append(vuln)
            
            # Display vulnerabilities by severity
            for severity, vulns in severity_groups.items():
                if not vulns:
                    continue
                
                # Choose color based on severity
                if severity == "Critical":
                    color = Colors.RED
                elif severity == "High":
                    color = Colors.MAGENTA
                elif severity == "Medium":
                    color = Colors.YELLOW
                elif severity == "Low":
                    color = Colors.BLUE
                else:
                    color = Colors.RESET
                
                print(f"  {color}{Colors.BOLD}{severity}{Colors.RESET} ({len(vulns)}):")
                
                for vuln in vulns:
                    name = vuln.get("name", "Unknown")
                    host = vuln.get("host", "")
                    port = vuln.get("port", "")
                    cve = vuln.get("cve", "N/A")
                    
                    print(f"    {color}[{severity}]{Colors.RESET} {name}")
                    if host and port:
                        print(f"      Target: {host}:{port}")
                    if cve and cve != "N/A":
                        print(f"      CVE: {cve}")
                    
                    # Truncate description for display
                    description = vuln.get("description", "")
                    if description:
                        max_desc_len = 80
                        if len(description) > max_desc_len:
                            description = description[:max_desc_len] + "..."
                        print(f"      Description: {description}")
                    
                    print()  # Add space between vulnerabilities
        
        # Display exploit results if available
        if "exploits" in scan_results:
            exploits = scan_results["exploits"]
            
            # Count successful exploits
            successful = len([e for e in exploits if e.get("status") == "success"])
            failed = len([e for e in exploits if e.get("status") == "failure"])
            
            print(f"\n{Colors.BOLD}Exploitation Results:{Colors.RESET}")
            print(f"  Attempted: {len(exploits)}")
            print(f"  Successful: {Colors.GREEN}{successful}{Colors.RESET}")
            print(f"  Failed: {Colors.RED}{failed}{Colors.RESET}")
            
            # Display successful exploits
            if successful > 0:
                print(f"\n  {Colors.GREEN}{Colors.BOLD}Successful Exploits:{Colors.RESET}")
                for exploit in exploits:
                    if exploit.get("status") == "success":
                        target = exploit.get("target", "")
                        exploit_name = exploit.get("exploit", "")
                        
                        # Get vulnerability info if available
                        vuln_info = ""
                        if "vulnerability" in exploit:
                            vuln = exploit["vulnerability"]
                            vuln_name = vuln.get("name", "")
                            if vuln_name:
                                vuln_info = f" ({vuln_name})"
                        
                        print(f"    {Colors.GREEN}✓{Colors.RESET} {exploit_name}")
                        print(f"      Target: {target}{vuln_info}")
                        print()
        
        # Display script generation results if available
        if "scripts" in scan_results:
            scripts = scan_results["scripts"]
            
            print(f"\n{Colors.BOLD}Generated Scripts:{Colors.RESET}")
            for script in scripts:
                script_type = script.get("script_type", "unknown")
                filename = script.get("filename", "")
                target = script.get("target", "")
                vuln = script.get("vulnerability", "")
                
                if script.get("type") == "enumeration":
                    print(f"  {Colors.CYAN}[Enumeration]{Colors.RESET} {filename}")
                elif script.get("type") == "post-exploitation":
                    print(f"  {Colors.MAGENTA}[Post-Exploitation]{Colors.RESET} {filename}")
                else:
                    print(f"  {Colors.YELLOW}[Exploit]{Colors.RESET} {filename}")
                
                print(f"    Target: {target}")
                if vuln:
                    print(f"    Vulnerability: {vuln}")
                print()
        
        # Display AI analysis if available
        if "ai_analysis" in scan_results:
            ai_analysis = scan_results["ai_analysis"]
            
            print(f"\n{Colors.BOLD}AI Analysis:{Colors.RESET}")
            
            # Display overall summary
            if "overall_summary" in ai_analysis:
                summary = ai_analysis["overall_summary"]
                security_rating = summary.get("security_rating", "Unknown")
                
                # Color based on rating
                if security_rating == "Critical":
                    rating_color = Colors.RED
                elif security_rating == "Poor":
                    rating_color = Colors.MAGENTA
                elif security_rating == "Fair":
                    rating_color = Colors.YELLOW
                elif security_rating == "Good":
                    rating_color = Colors.GREEN
                else:
                    rating_color = Colors.RESET
                
                print(f"  {Colors.BOLD}Security Rating:{Colors.RESET} {rating_color}{security_rating}{Colors.RESET}")
                
                # Display risk assessment
                risk_assessment = summary.get("risk_assessment", "")
                if risk_assessment:
                    print(f"  {Colors.BOLD}Risk Assessment:{Colors.RESET} {risk_assessment}")
                
                # Display key recommendations
                recommendations = summary.get("key_recommendations", [])
                if recommendations:
                    print(f"  {Colors.BOLD}Key Recommendations:{Colors.RESET}")
                    for i, rec in enumerate(recommendations, 1):
                        print(f"    {i}. {rec}")
            
            print()  # Add extra space
    
    def print_info(self, message):
        """
        Print an informational message.
        
        Args:
            message (str): Message to display
        """
        if self.quiet:
            return
        
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} {message}")
    
    def print_success(self, message):
        """
        Print a success message.
        
        Args:
            message (str): Message to display
        """
        if self.quiet:
            return
        
        print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} {message}")
    
    def print_warning(self, message):
        """
        Print a warning message.
        
        Args:
            message (str): Message to display
        """
        if self.quiet:
            return
        
        print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} {message}")
    
    def print_error(self, message):
        """
        Print an error message.
        
        Args:
            message (str): Message to display
        """
        if self.quiet:
            return
        
        print(f"{Colors.RED}[ERROR]{Colors.RESET} {message}")
    
    def print_debug(self, message):
        """
        Print a debug message.
        
        Args:
            message (str): Message to display
        """
        if self.quiet:
            return
        
        print(f"{Colors.MAGENTA}[DEBUG]{Colors.RESET} {message}") 