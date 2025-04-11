#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL Script Generator Module
============================

This module handles generation of custom exploitation scripts using AI.
"""

import os
import re
import json
import base64
import subprocess
import requests
from datetime import datetime
from .logger import LoggerWrapper

class ScriptGenerator:
    """
    ScriptGenerator class for generating custom exploitation scripts.
    """
    
    def __init__(self, script_type="python", output_dir="./scripts", script_format="raw", 
                 model="artifish/llama3.2-uncensored", api_url=None, api_key=None, timeout=60):
        """
        Initialize the script generator.
        
        Args:
            script_type (str): Type of script to generate (python/bash/ruby)
            output_dir (str): Directory to save generated scripts
            script_format (str): Format to save scripts (raw/base64)
            model (str): AI model to use for generation
            api_url (str, optional): URL for API-based models
            api_key (str, optional): API key for API-based models
            timeout (int): Request timeout in seconds
        """
        self.script_type = script_type
        self.output_dir = output_dir
        self.script_format = script_format
        self.model = model
        self.api_url = api_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.api_key = api_key or os.environ.get("OLLAMA_API_KEY")
        self.timeout = timeout
        self.logger = LoggerWrapper("ScriptGenerator")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Set file extension based on script type
        self.extensions = {
            "python": ".py",
            "bash": ".sh",
            "ruby": ".rb"
        }
    
    def is_ollama_available(self):
        """
        Check if Ollama is available.
        
        Returns:
            bool: True if Ollama is available, False otherwise
        """
        try:
            response = requests.get(f"{self.api_url}/api/tags", timeout=2)
            return response.status_code == 200
        except Exception:
            return False
    
    def generate_with_ollama(self, prompt, model_name):
        """
        Generate text using Ollama API.
        
        Args:
            prompt (str): The prompt to send to the model
            model_name (str): The model to use
        
        Returns:
            str: Generated text, or None if failed
        """
        try:
            # API request to Ollama
            response = requests.post(
                f"{self.api_url}/api/generate",
                json={
                    "model": model_name,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get("response", "")
            else:
                self.logger.error(f"Error from Ollama API: {response.text}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error generating with Ollama: {str(e)}")
            return None
    
    def extract_code_from_response(self, response_text, script_type):
        """
        Extract code block from model response.
        
        Args:
            response_text (str): Full text response from the model
            script_type (str): Type of script to extract (python/bash/ruby)
        
        Returns:
            str: Extracted code, or the full response if no code block found
        """
        # Define patterns for code blocks
        patterns = [
            r'```(?:' + script_type + r')?\s*([\s\S]*?)\s*```',  # Markdown code block with or without language
            r'<code(?:\s+class="' + script_type + r'")?>([^<]+)</code>',  # HTML-style code block
            r'<pre>([^<]+)</pre>'  # Pre-formatted text block
        ]
        
        # Try each pattern to extract code
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                return matches[0].strip()
        
        # If no code block found, try to find the code by identifying common headers
        if script_type == "python":
            # Look for Python shebang or common Python patterns
            if "#!/usr/bin/env python" in response_text or "import " in response_text:
                return response_text.strip()
        elif script_type == "bash":
            # Look for bash shebang or common bash patterns
            if "#!/bin/bash" in response_text or "#!/bin/sh" in response_text:
                return response_text.strip()
        elif script_type == "ruby":
            # Look for Ruby shebang or common Ruby patterns
            if "#!/usr/bin/env ruby" in response_text or "require " in response_text:
                return response_text.strip()
        
        # If no code block or identifiable code found, return the full response
        return response_text.strip()
    
    def generate_exploit_script(self, vulnerability, host_info=None):
        """
        Generate an exploitation script for a specific vulnerability.
        
        Args:
            vulnerability (dict): Vulnerability information
            host_info (dict, optional): Host information
        
        Returns:
            dict: Generated script information
        """
        # Extract key information
        vuln_name = vulnerability.get("name", "Unknown Vulnerability")
        vuln_description = vulnerability.get("description", "No description")
        vuln_host = vulnerability.get("host", "localhost")
        vuln_port = vulnerability.get("port", "80")
        vuln_severity = vulnerability.get("severity", "Unknown")
        vuln_cve = vulnerability.get("cve", "N/A")
        
        # Limit description length for prompt
        vuln_description = vuln_description[:500] + "..." if len(vuln_description) > 500 else vuln_description
        
        # Add host info if available
        host_context = ""
        if host_info:
            os_info = host_info.get("os", [{"name": "Unknown OS"}])[0].get("name", "Unknown OS")
            services = [f"{p['portid']}/{p['protocol']}: {p['service'].get('name', 'unknown')}" 
                      for p in host_info.get("ports", []) if p.get("state") == "open"]
            
            host_context = f"""
Additional host information:
- Operating System: {os_info}
- Open services: {', '.join(services[:5])}
"""
        
        # Build prompt based on script type
        if self.script_type == "python":
            script_prompt = f"""
Write a detailed Python exploitation script for the following vulnerability:

Vulnerability: {vuln_name}
Host: {vuln_host}
Port: {vuln_port}
Severity: {vuln_severity}
CVE (if applicable): {vuln_cve}
Description: {vuln_description}
{host_context}

Requirements for the Python script:
1. Include proper error handling and timeout management
2. Add clear comments explaining the exploitation process
3. Make the script robust with connection retries and error detection
4. Add a verification step to confirm if the exploit was successful
5. Provide clean output showing the exploit status
6. Include appropriate library imports (requests, socket, etc.)
7. Use a class-based structure for better organization

Provide ONLY the Python code without any additional explanation.
"""
        elif self.script_type == "bash":
            script_prompt = f"""
Write a detailed Bash exploitation script for the following vulnerability:

Vulnerability: {vuln_name}
Host: {vuln_host}
Port: {vuln_port}
Severity: {vuln_severity}
CVE (if applicable): {vuln_cve}
Description: {vuln_description}
{host_context}

Requirements for the Bash script:
1. Include proper error handling and timeout management
2. Add clear comments explaining the exploitation process
3. Use bash best practices for robust script execution
4. Add a verification step to confirm if the exploit was successful
5. Provide clean output showing the exploit status
6. Use only common Linux/Unix tools that would be available on Kali Linux
7. Include appropriate shebang line and execution permissions note

Provide ONLY the Bash code without any additional explanation.
"""
        elif self.script_type == "ruby":
            script_prompt = f"""
Write a detailed Ruby exploitation script for the following vulnerability:

Vulnerability: {vuln_name}
Host: {vuln_host}
Port: {vuln_port}
Severity: {vuln_severity}
CVE (if applicable): {vuln_cve}
Description: {vuln_description}
{host_context}

Requirements for the Ruby script:
1. Include proper error handling and timeout management
2. Add clear comments explaining the exploitation process
3. Make the script robust with connection retries and error detection
4. Add a verification step to confirm if the exploit was successful
5. Provide clean output showing the exploit status
6. Include appropriate library imports (net/http, socket, etc.)
7. Use a class-based structure for better organization
8. Focus on Metasploit-style coding conventions when applicable

Provide ONLY the Ruby code without any additional explanation.
"""
        
        # Generate the script
        if self.is_ollama_available():
            self.logger.info(f"Generating {self.script_type} exploit script for {vuln_name}")
            script_text = self.generate_with_ollama(script_prompt, self.model)
            
            if script_text:
                # Extract the code from the response
                code = self.extract_code_from_response(script_text, self.script_type)
                
                # Create a filename
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                safe_vuln_name = re.sub(r'[^\w\-_]', '_', vuln_name.lower())
                filename = f"exploit_{safe_vuln_name}_{timestamp}{self.extensions.get(self.script_type, '.txt')}"
                filepath = os.path.join(self.output_dir, filename)
                
                # Encode if specified
                content = code
                if self.script_format == "base64":
                    content = base64.b64encode(code.encode()).decode()
                
                # Save the script
                with open(filepath, 'w') as f:
                    f.write(content)
                
                self.logger.info(f"Saved exploit script to {filepath}")
                
                # Return script information
                return {
                    "vulnerability": vuln_name,
                    "filename": filename,
                    "filepath": filepath,
                    "script_type": self.script_type,
                    "encoded": self.script_format == "base64",
                    "target": f"{vuln_host}:{vuln_port}",
                    "cve": vuln_cve
                }
            else:
                self.logger.error(f"Failed to generate script for {vuln_name}")
                return None
        else:
            self.logger.warning("Ollama is not available, cannot generate scripts")
            return None
    
    def generate_enum_script(self, target, services=None):
        """
        Generate an enumeration script for a target.
        
        Args:
            target (str): Target IP or hostname
            services (list, optional): List of detected services
        
        Returns:
            dict: Generated script information
        """
        # Build services context
        services_context = ""
        if services:
            services_list = [f"- {service['name']} on port {service['port']}" for service in services[:10]]
            services_context = f"Detected services:\n" + "\n".join(services_list)
        
        # Build prompt based on script type
        if self.script_type == "python":
            script_prompt = f"""
Write a detailed Python enumeration script for the following target:

Target: {target}
{services_context}

Requirements for the Python script:
1. Create a comprehensive enumeration tool that scans and analyzes the target
2. Include modules for service fingerprinting and basic vulnerability detection
3. Add clear output formatting with potential security issues highlighted
4. Include proper error handling and timeout management
5. Make the script multi-threaded for better performance
6. Include appropriate library imports
7. Use a class-based structure for better organization

Provide ONLY the Python code without any additional explanation.
"""
        elif self.script_type == "bash":
            script_prompt = f"""
Write a detailed Bash enumeration script for the following target:

Target: {target}
{services_context}

Requirements for the Bash script:
1. Create a comprehensive enumeration tool that scans and analyzes the target
2. Use common Linux tools (nmap, netcat, curl, etc.) for service discovery and analysis
3. Add clear output formatting with potential security issues highlighted
4. Include proper error handling and timeout management
5. Add color-coded output for better readability
6. Include appropriate shebang line and execution permissions note
7. Focus on performance and thoroughness

Provide ONLY the Bash code without any additional explanation.
"""
        elif self.script_type == "ruby":
            script_prompt = f"""
Write a detailed Ruby enumeration script for the following target:

Target: {target}
{services_context}

Requirements for the Ruby script:
1. Create a comprehensive enumeration tool that scans and analyzes the target
2. Include modules for service fingerprinting and basic vulnerability detection
3. Add clear output formatting with potential security issues highlighted
4. Include proper error handling and timeout management
5. Make the script multi-threaded for better performance
6. Include appropriate library imports
7. Use a class-based structure for better organization
8. Focus on Metasploit-style coding conventions

Provide ONLY the Ruby code without any additional explanation.
"""
        
        # Generate the script
        if self.is_ollama_available():
            self.logger.info(f"Generating {self.script_type} enumeration script for {target}")
            script_text = self.generate_with_ollama(script_prompt, self.model)
            
            if script_text:
                # Extract the code from the response
                code = self.extract_code_from_response(script_text, self.script_type)
                
                # Create a filename
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                safe_target = re.sub(r'[^\w\-_]', '_', target)
                filename = f"enum_{safe_target}_{timestamp}{self.extensions.get(self.script_type, '.txt')}"
                filepath = os.path.join(self.output_dir, filename)
                
                # Encode if specified
                content = code
                if self.script_format == "base64":
                    content = base64.b64encode(code.encode()).decode()
                
                # Save the script
                with open(filepath, 'w') as f:
                    f.write(content)
                
                self.logger.info(f"Saved enumeration script to {filepath}")
                
                # Return script information
                return {
                    "type": "enumeration",
                    "filename": filename,
                    "filepath": filepath,
                    "script_type": self.script_type,
                    "encoded": self.script_format == "base64",
                    "target": target
                }
            else:
                self.logger.error(f"Failed to generate enumeration script for {target}")
                return None
        else:
            self.logger.warning("Ollama is not available, cannot generate scripts")
            return None
    
    def generate_post_exploit_script(self, target, os_info=None):
        """
        Generate a post-exploitation script for a target.
        
        Args:
            target (str): Target IP or hostname
            os_info (dict, optional): Operating system information
        
        Returns:
            dict: Generated script information
        """
        # Build OS context
        os_context = ""
        if os_info:
            os_name = os_info.get("name", "Unknown")
            os_context = f"Operating System: {os_name}"
        
        # Build prompt based on script type
        if self.script_type == "python":
            script_prompt = f"""
Write a detailed Python post-exploitation script for the following target:

Target: {target}
{os_context}

Requirements for the Python script:
1. Create a post-exploitation tool that gathers system information and establishes persistence
2. Include modules for credential harvesting, network reconnaissance, and privilege escalation
3. Add data exfiltration capabilities with encryption
4. Include proper error handling and anti-detection measures
5. Make the script stealthy and resilient
6. Include appropriate library imports
7. Use a class-based structure for better organization

Provide ONLY the Python code without any additional explanation.
"""
        elif self.script_type == "bash":
            script_prompt = f"""
Write a detailed Bash post-exploitation script for the following target:

Target: {target}
{os_context}

Requirements for the Bash script:
1. Create a post-exploitation tool that gathers system information and establishes persistence
2. Include modules for credential harvesting, network reconnaissance, and privilege escalation
3. Add data exfiltration capabilities
4. Include proper error handling and anti-detection measures
5. Make the script stealthy and resilient
6. Use only common Linux/Unix tools
7. Include appropriate shebang line and execution permissions note

Provide ONLY the Bash code without any additional explanation.
"""
        elif self.script_type == "ruby":
            script_prompt = f"""
Write a detailed Ruby post-exploitation script for the following target:

Target: {target}
{os_context}

Requirements for the Ruby script:
1. Create a post-exploitation tool that gathers system information and establishes persistence
2. Include modules for credential harvesting, network reconnaissance, and privilege escalation
3. Add data exfiltration capabilities with encryption
4. Include proper error handling and anti-detection measures
5. Make the script stealthy and resilient
6. Include appropriate library imports
7. Use a class-based structure for better organization
8. Focus on Metasploit-style post modules as inspiration

Provide ONLY the Ruby code without any additional explanation.
"""
        
        # Generate the script
        if self.is_ollama_available():
            self.logger.info(f"Generating {self.script_type} post-exploitation script for {target}")
            script_text = self.generate_with_ollama(script_prompt, self.model)
            
            if script_text:
                # Extract the code from the response
                code = self.extract_code_from_response(script_text, self.script_type)
                
                # Create a filename
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                safe_target = re.sub(r'[^\w\-_]', '_', target)
                filename = f"post_{safe_target}_{timestamp}{self.extensions.get(self.script_type, '.txt')}"
                filepath = os.path.join(self.output_dir, filename)
                
                # Encode if specified
                content = code
                if self.script_format == "base64":
                    content = base64.b64encode(code.encode()).decode()
                
                # Save the script
                with open(filepath, 'w') as f:
                    f.write(content)
                
                self.logger.info(f"Saved post-exploitation script to {filepath}")
                
                # Return script information
                return {
                    "type": "post-exploitation",
                    "filename": filename,
                    "filepath": filepath,
                    "script_type": self.script_type,
                    "encoded": self.script_format == "base64",
                    "target": target
                }
            else:
                self.logger.error(f"Failed to generate post-exploitation script for {target}")
                return None
        else:
            self.logger.warning("Ollama is not available, cannot generate scripts")
            return None
    
    def generate_scripts(self, scan_results):
        """
        Generate appropriate scripts based on scan results.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            list: List of generated script information
        """
        generated_scripts = []
        
        # Extract targets, vulnerabilities, and host information
        hosts = scan_results.get("hosts", [])
        vulnerabilities = scan_results.get("vulnerabilities", [])
        
        # Generate enumeration scripts for each host
        for host in hosts:
            target = next((addr["addr"] for addr in host.get("addresses", []) if addr.get("addrtype") == "ipv4"), None)
            if not target:
                continue
            
            # Extract service information
            services = []
            for port in host.get("ports", []):
                if port.get("state") == "open":
                    service_name = port.get("service", {}).get("name", "unknown")
                    services.append({
                        "name": service_name,
                        "port": port.get("portid", "0")
                    })
            
            # Generate enumeration script
            enum_script = self.generate_enum_script(target, services)
            if enum_script:
                generated_scripts.append(enum_script)
        
        # Generate exploit scripts for each vulnerability
        for vuln in vulnerabilities:
            # Skip if no host or port information
            if not vuln.get("host") or not vuln.get("port"):
                continue
            
            # Find host information for this vulnerability
            target_host = vuln["host"]
            host_info = next((h for h in hosts if any(a["addr"] == target_host for a in h.get("addresses", []))), None)
            
            # Generate exploit script
            exploit_script = self.generate_exploit_script(vuln, host_info)
            if exploit_script:
                generated_scripts.append(exploit_script)
        
        # If there were successful exploits, generate post-exploitation scripts
        if "exploits" in scan_results:
            successful_exploits = [e for e in scan_results["exploits"] if e.get("status") == "success"]
            
            for exploit in successful_exploits:
                target = exploit.get("target", "").split(":")[0]  # Extract IP from target
                if not target:
                    continue
                
                # Find host information for this target
                host_info = next((h for h in hosts if any(a["addr"] == target for a in h.get("addresses", []))), None)
                
                # Extract OS information if available
                os_info = None
                if host_info and host_info.get("os"):
                    os_info = host_info["os"][0] if host_info["os"] else None
                
                # Generate post-exploitation script
                post_script = self.generate_post_exploit_script(target, os_info)
                if post_script:
                    generated_scripts.append(post_script)
        
        return generated_scripts
    
    def execute_script(self, script_info):
        """
        Execute a generated script.
        
        Args:
            script_info (dict): Script information
        
        Returns:
            dict: Execution results
        """
        filepath = script_info.get("filepath")
        if not filepath or not os.path.exists(filepath):
            self.logger.error(f"Script file not found: {filepath}")
            return {"status": "error", "message": "Script file not found"}
        
        # Decode if encoded
        if script_info.get("encoded"):
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                
                decoded_content = base64.b64decode(content).decode()
                temp_filepath = filepath + ".decoded"
                
                with open(temp_filepath, 'w') as f:
                    f.write(decoded_content)
                
                filepath = temp_filepath
            except Exception as e:
                self.logger.error(f"Error decoding script: {str(e)}")
                return {"status": "error", "message": f"Error decoding script: {str(e)}"}
        
        # Set execution command based on script type
        if script_info.get("script_type") == "python":
            cmd = ["python3", filepath]
        elif script_info.get("script_type") == "bash":
            # Make sure the script is executable
            os.chmod(filepath, 0o755)
            cmd = ["bash", filepath]
        elif script_info.get("script_type") == "ruby":
            cmd = ["ruby", filepath]
        else:
            self.logger.error(f"Unsupported script type: {script_info.get('script_type')}")
            return {"status": "error", "message": f"Unsupported script type: {script_info.get('script_type')}"}
        
        # Execute the script
        self.logger.info(f"Executing script: {' '.join(cmd)}")
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=self.timeout)
            
            # Clean up temporary file if created
            if filepath.endswith(".decoded") and os.path.exists(filepath):
                os.unlink(filepath)
            
            # Check execution status
            if process.returncode == 0:
                return {
                    "status": "success",
                    "returncode": process.returncode,
                    "stdout": stdout.decode(),
                    "stderr": stderr.decode(),
                    "script": script_info
                }
            else:
                return {
                    "status": "failure",
                    "returncode": process.returncode,
                    "stdout": stdout.decode(),
                    "stderr": stderr.decode(),
                    "script": script_info
                }
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            
            # Clean up temporary file if created
            if filepath.endswith(".decoded") and os.path.exists(filepath):
                os.unlink(filepath)
            
            return {
                "status": "timeout",
                "message": f"Script execution timed out after {self.timeout} seconds",
                "stdout": stdout.decode() if stdout else "",
                "stderr": stderr.decode() if stderr else "",
                "script": script_info
            }
        except Exception as e:
            # Clean up temporary file if created
            if filepath.endswith(".decoded") and os.path.exists(filepath):
                os.unlink(filepath)
            
            self.logger.error(f"Error executing script: {str(e)}")
            return {
                "status": "error",
                "message": f"Error executing script: {str(e)}",
                "script": script_info
            }
    
    def execute_scripts(self, scripts):
        """
        Execute a list of generated scripts.
        
        Args:
            scripts (list): List of script information dictionaries
        
        Returns:
            list: List of execution results
        """
        results = []
        
        for script in scripts:
            result = self.execute_script(script)
            results.append(result)
        
        return results 