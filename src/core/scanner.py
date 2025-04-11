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