#!/usr/bin/env python3
"""
Script generation module for AI_MAL
"""

import asyncio
import json
import logging
import os
import shutil
from typing import Dict, List, Optional, Any
from datetime import datetime
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

class ScriptGenerator:
    def __init__(self):
        self.scripts_dir = os.getenv('GENERATED_SCRIPTS_DIR', 'generated_scripts')
        os.makedirs(self.scripts_dir, exist_ok=True)
        # Check for required tools
        self._check_dependencies()
        
    def _check_dependencies(self):
        """Check for required dependencies for script execution"""
        # Check Python3
        if not shutil.which('python3'):
            logger.warning("Python3 not found in PATH. Python scripts may not execute.")
            
        # Check Bash
        if not shutil.which('bash'):
            logger.warning("Bash not found in PATH. Bash scripts may not execute.")
            
        # Check Ruby
        if not shutil.which('ruby'):
            logger.warning("Ruby not found in PATH. Ruby scripts may not execute.")

    async def generate_scripts(
        self,
        scan_results: Dict[str, Any],
        script_type: str = 'python'
    ) -> List[Dict[str, Any]]:
        """
        Generate custom exploitation scripts based on scan results
        """
        try:
            scripts = []
            
            if script_type == 'python':
                scripts.extend(await self._generate_python_scripts(scan_results))
            elif script_type == 'bash':
                scripts.extend(await self._generate_bash_scripts(scan_results))
            elif script_type == 'ruby':
                scripts.extend(await self._generate_ruby_scripts(scan_results))
            
            return scripts
            
        except Exception as e:
            logger.error(f"Error generating scripts: {str(e)}")
            return []

    async def execute_scripts(self, scripts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Execute generated scripts
        """
        try:
            results = []
            
            for script in scripts:
                # Skip scripts with invalid paths
                script_path = script.get('path')
                if not script_path or not os.path.exists(script_path):
                    logger.warning(f"Script path not found: {script_path}")
                    results.append({
                        "script": script,
                        "result": {
                            "status": "error",
                            "error": "Script file not found"
                        }
                    })
                    continue
                
                # Make script executable
                os.chmod(script_path, 0o755)
                
                # Execute script
                logger.info(f"Executing script: {script['name']} ({script['type']})")
                result = await self._execute_script(script)
                results.append({
                    "script": script,
                    "result": result
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Error executing scripts: {str(e)}")
            return []

    async def _generate_python_scripts(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate Python exploitation scripts
        """
        try:
            scripts = []
            
            # Generate port scanner with target info
            port_scanner = self._generate_port_scanner(scan_results)
            scripts.append(port_scanner)
            
            # Generate service enumerator
            service_enum = self._generate_service_enum(scan_results)
            scripts.append(service_enum)
            
            # Generate vulnerability scanner
            vuln_scanner = self._generate_vuln_scanner(scan_results)
            scripts.append(vuln_scanner)
            
            return scripts
            
        except Exception as e:
            logger.error(f"Error generating Python scripts: {str(e)}")
            return []

    async def _generate_bash_scripts(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate Bash exploitation scripts
        """
        try:
            scripts = []
            
            # Generate port scanner
            port_scanner = self._generate_bash_port_scanner(scan_results)
            scripts.append(port_scanner)
            
            # Generate service enumerator
            service_enum = self._generate_bash_service_enum(scan_results)
            scripts.append(service_enum)
            
            # Generate vulnerability scanner
            vuln_scanner = self._generate_bash_vuln_scanner(scan_results)
            scripts.append(vuln_scanner)
            
            return scripts
            
        except Exception as e:
            logger.error(f"Error generating Bash scripts: {str(e)}")
            return []

    async def _generate_ruby_scripts(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate Ruby exploitation scripts
        """
        try:
            scripts = []
            
            # Generate port scanner
            port_scanner = self._generate_ruby_port_scanner(scan_results)
            scripts.append(port_scanner)
            
            # Generate service enumerator
            service_enum = self._generate_ruby_service_enum(scan_results)
            scripts.append(service_enum)
            
            # Generate vulnerability scanner
            vuln_scanner = self._generate_ruby_vuln_scanner(scan_results)
            scripts.append(vuln_scanner)
            
            return scripts
            
        except Exception as e:
            logger.error(f"Error generating Ruby scripts: {str(e)}")
            return []

    def _generate_port_scanner(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Python port scanner script
        """
        try:
            # Extract target from scan results
            target = scan_results.get("scan_info", {}).get("target", "127.0.0.1")
            
            script_content = f"""#!/usr/bin/env python3
# Port scanner for target: {target}
# Generated by AI_MAL on {datetime.now().isoformat()}

import socket
import sys
import argparse
import concurrent.futures
from datetime import datetime

def scan_port(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        s.close()
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            return port, True, service
        return port, False, None
    except Exception as e:
        return port, False, None

def scan_ports(target, start_port=1, end_port=1000, threads=50):
    print(f"[*] Starting scan of {{target}} on ports {{start_port}}-{{end_port}}")
    start_time = datetime.now()
    
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for port in range(start_port, end_port + 1):
            futures.append(executor.submit(scan_port, target, port))
        
        for future in concurrent.futures.as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))
                print(f"[+] Port {{port}} open - {{service}}")
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print(f"\\n[*] Scan completed in {{duration:.2f}} seconds")
    print(f"[*] Found {{len(open_ports)}} open ports on {{target}}")
    
    return open_ports

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple port scanner')
    parser.add_argument('target', nargs='?', default='{target}', help='Target IP address')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range to scan (e.g. 1-1000)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads to use')
    
    args = parser.parse_args()
    
    # Parse port range
    try:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        else:
            start_port = end_port = int(args.ports)
    except ValueError:
        print("Invalid port range. Use format: start-end (e.g. 1-1000)")
        sys.exit(1)
    
    scan_ports(args.target, start_port, end_port, args.threads)
"""
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            script_path = os.path.join(self.scripts_dir, f'port_scanner_{timestamp}.py')
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            return {
                "name": "port_scanner",
                "type": "python",
                "path": script_path,
                "description": f"Port scanning script for {target}"
            }
            
        except Exception as e:
            logger.error(f"Error generating port scanner: {str(e)}")
            return self._generate_fallback_script("port_scanner", "python")

    def _generate_service_enum(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Python service enumeration script
        """
        try:
            # Extract target and open ports from scan results
            target = scan_results.get("scan_info", {}).get("target", "127.0.0.1")
            
            # Extract ports discovered in scan
            ports = []
            for host in scan_results.get("hosts", []):
                for port_info in host.get("ports", []):
                    if port_info.get("state") == "open":
                        ports.append(str(port_info.get("port")))
            
            port_list = ",".join(ports) if ports else "22,80,443"
            
            script_content = f"""#!/usr/bin/env python3
# Service enumeration script for target: {target}
# Generated by AI_MAL on {datetime.now().isoformat()}

import socket
import sys
import argparse
import concurrent.futures
from datetime import datetime

def enumerate_service(target, port):
    try:
        # Try to get service name
        try:
            service = socket.getservbyport(int(port))
        except:
            service = "unknown"
            
        # Try to connect and get banner
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, int(port)))
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
        except:
            banner = ""
            
        return port, service, banner
    except Exception as e:
        return port, "error", str(e)

def enumerate_services(target, ports, threads=10):
    print(f"[*] Starting service enumeration on {{target}} for ports: {{ports}}")
    start_time = datetime.now()
    
    port_list = [p.strip() for p in ports.split(',')]
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for port in port_list:
            futures.append(executor.submit(enumerate_service, target, port))
        
        for future in concurrent.futures.as_completed(futures):
            port, service, banner = future.result()
            results.append((port, service, banner))
            print(f"[+] Port {{port}} - {{service}}")
            if banner:
                print(f"    Banner: {{banner}}")
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print(f"\\n[*] Enumeration completed in {{duration:.2f}} seconds")
    return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Service enumeration script')
    parser.add_argument('target', nargs='?', default='{target}', help='Target IP address')
    parser.add_argument('-p', '--ports', default='{port_list}', help='Ports to scan (comma-separated)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use')
    
    args = parser.parse_args()
    
    enumerate_services(args.target, args.ports, args.threads)
"""
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            script_path = os.path.join(self.scripts_dir, f'service_enum_{timestamp}.py')
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            return {
                "name": "service_enum",
                "type": "python",
                "path": script_path,
                "description": f"Service enumeration script for {target}"
            }
            
        except Exception as e:
            logger.error(f"Error generating service enumerator: {str(e)}")
            return self._generate_fallback_script("service_enum", "python")

    def _generate_vuln_scanner(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Python vulnerability scanner script
        """
        try:
            # Extract target from scan results
            target = scan_results.get("scan_info", {}).get("target", "127.0.0.1")
            
            # Extract ports with services
            services = []
            for host in scan_results.get("hosts", []):
                for port_info in host.get("ports", []):
                    if port_info.get("state") == "open":
                        port = port_info.get("port")
                        service = port_info.get("service", "unknown")
                        services.append(f"{port}:{service}")
            
            services_str = ", ".join(services) if services else "no open ports found"
            
            script_content = f"""#!/usr/bin/env python3
# Vulnerability scanner for target: {target} 
# Open services: {services_str}
# Generated by AI_MAL on {datetime.now().isoformat()}

import requests
import sys
import argparse
import concurrent.futures
from datetime import datetime
import socket

# Common vulnerabilities to check
VULNERABILITIES = {{
    'http': [
        # Check for common web vulnerabilities
        ('/robots.txt', 'Directory listing'),
        ('/admin', 'Admin panel'),
        ('/wp-login.php', 'WordPress site'),
        ('/phpmyadmin', 'phpMyAdmin panel'),
        ('/manager/html', 'Tomcat Manager')
    ],
    'ssh': [
        # SSH checks are mostly version-based, handled separately
    ],
    'ftp': [
        # Check for anonymous FTP
        ('anonymous', 'Anonymous FTP access')
    ],
    'smtp': [
        # SMTP checks
        ('VRFY root', 'VRFY command enabled')
    ]
}}

def check_web_path(target, port, path, description):
    try:
        protocol = 'https' if port == 443 else 'http'
        url = f"{{protocol}}://{{target}}:{{port}}{{path}}"
        response = requests.get(url, timeout=5, verify=False)
        if response.status_code != 404:
            return True, f"Found: {{description}} (Status: {{response.status_code}})"
        return False, None
    except Exception:
        return False, None

def check_ftp_anonymous(target, port):
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=5)
        ftp.login('anonymous', 'anonymous@example.com')
        ftp.quit()
        return True, "Anonymous FTP access allowed"
    except Exception:
        return False, None

def check_ssh_version(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        if 'SSH-1.99' in banner or 'SSH-1.' in banner:
            return True, f"Vulnerable SSH version: {{banner}}"
        return False, None
    except Exception:
        return False, None

def check_smtp_commands(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        s.recv(1024)  # Banner
        
        # Check VRFY
        s.send(b'VRFY root\\r\\n')
        response = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        if not response.startswith('5'):  # Not rejected
            return True, "SMTP VRFY command enabled"
        return False, None
    except Exception:
        return False, None

def check_vulnerabilities(target, port, service):
    results = []
    
    try:
        service_name = service.lower()
        
        # Web checks
        if service_name in ['http', 'https', 'www'] or port in [80, 443, 8080, 8443]:
            for path, desc in VULNERABILITIES.get('http', []):
                is_vuln, details = check_web_path(target, port, path, desc)
                if is_vuln:
                    results.append(details)
        
        # SSH checks
        elif service_name == 'ssh' or port == 22:
            is_vuln, details = check_ssh_version(target, port)
            if is_vuln:
                results.append(details)
        
        # FTP checks
        elif service_name == 'ftp' or port == 21:
            is_vuln, details = check_ftp_anonymous(target, port)
            if is_vuln:
                results.append(details)
        
        # SMTP checks
        elif service_name == 'smtp' or port == 25:
            is_vuln, details = check_smtp_commands(target, port)
            if is_vuln:
                results.append(details)
                
    except Exception as e:
        results.append(f"Error checking port {{port}}: {{str(e)}}")
    
    return port, service, results

def scan_vulnerabilities(target, ports_services, threads=5):
    print(f"[*] Starting vulnerability scan on {{target}}")
    start_time = datetime.now()
    
    port_service_list = []
    for ps in ports_services.split(','):
        if ':' in ps:
            port, service = ps.split(':', 1)
            port_service_list.append((port.strip(), service.strip()))
        else:
            port_service_list.append((ps.strip(), 'unknown'))
    
    vulnerabilities = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for port, service in port_service_list:
            futures.append(executor.submit(check_vulnerabilities, target, int(port), service))
        
        for future in concurrent.futures.as_completed(futures):
            port, service, results = future.result()
            if results:
                print(f"[+] Port {{port}} ({{service}}) has potential vulnerabilities:")
                for result in results:
                    print(f"    - {{result}}")
                    vulnerabilities.append((port, service, result))
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print(f"\\n[*] Vulnerability scan completed in {{duration:.2f}} seconds")
    print(f"[*] Found {{len(vulnerabilities)}} potential vulnerabilities")
    
    return vulnerabilities

if __name__ == '__main__':
    # Suppress InsecureRequestWarning for HTTPS requests
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except:
        pass
    
    parser = argparse.ArgumentParser(description='Simple vulnerability scanner')
    parser.add_argument('target', nargs='?', default='{target}', help='Target IP address')
    parser.add_argument('-p', '--ports', default='{",".join([s for s in services])}', 
                        help='Ports and services to scan (format: port:service,port:service)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads to use')
    
    args = parser.parse_args()
    
    scan_vulnerabilities(args.target, args.ports, args.threads)
"""
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            script_path = os.path.join(self.scripts_dir, f'vuln_scanner_{timestamp}.py')
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            return {
                "name": "vuln_scanner",
                "type": "python",
                "path": script_path,
                "description": f"Vulnerability scanning script for {target}"
            }
            
        except Exception as e:
            logger.error(f"Error generating vulnerability scanner: {str(e)}")
            return self._generate_fallback_script("vuln_scanner", "python")

    def _generate_fallback_script(self, name: str, script_type: str) -> Dict[str, Any]:
        """Generate a simple fallback script if the main generator fails"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if script_type == "python":
                extension = "py"
                content = f"""#!/usr/bin/env python3
# Fallback {name} script
# Generated by AI_MAL on {datetime.now().isoformat()}

import sys

print(f"Running {name} script...")
print(f"Usage: {sys.argv[0]} [target]")
print("This is a fallback script. The original script generation failed.")
"""
            elif script_type == "bash":
                extension = "sh"
                content = f"""#!/bin/bash
# Fallback {name} script
# Generated by AI_MAL on {datetime.now().isoformat()}

echo "Running {name} script..."
echo "Usage: $0 [target]"
echo "This is a fallback script. The original script generation failed."
"""
            elif script_type == "ruby":
                extension = "rb"
                content = f"""#!/usr/bin/env ruby
# Fallback {name} script
# Generated by AI_MAL on {datetime.now().isoformat()}

puts "Running {name} script..."
puts "Usage: #{$0} [target]"
puts "This is a fallback script. The original script generation failed."
"""
            else:
                extension = "txt"
                content = f"# Fallback {name} script\n# Generated by AI_MAL\n# Script generation failed."
                
            script_path = os.path.join(self.scripts_dir, f'{name}_{timestamp}.{extension}')
            with open(script_path, 'w') as f:
                f.write(content)
                
            return {
                "name": name,
                "type": script_type,
                "path": script_path,
                "description": f"Fallback {name} script (generation error occurred)"
            }
        except Exception as e:
            logger.error(f"Error generating fallback script: {str(e)}")
            return {
                "name": name,
                "type": script_type,
                "path": "",
                "description": "Script generation failed completely"
            }

    async def _execute_script(self, script: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a generated script
        """
        try:
            # Build command based on script type
            if script['type'] == 'python':
                cmd = ['python3', script['path']]
            elif script['type'] == 'bash':
                cmd = ['bash', script['path']]
            elif script['type'] == 'ruby':
                cmd = ['ruby', script['path']]
            else:
                raise ValueError(f"Unsupported script type: {script['type']}")
            
            # Default timeout of 3 minutes
            timeout = 180
            
            # Run script with timeout
            try:
                logger.debug(f"Running command: {' '.join(cmd)}")
                start_time = datetime.now()
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                if process.returncode != 0:
                    logger.error(f"Script execution failed: {stderr.decode()}")
                    return {
                        "status": "failed",
                        "error": stderr.decode(),
                        "output": stdout.decode(),
                        "duration": duration
                    }
                
                return {
                    "status": "success",
                    "output": stdout.decode(),
                    "duration": duration
                }
                
            except asyncio.TimeoutError:
                # Kill process on timeout
                try:
                    process.kill()
                except:
                    pass
                    
                logger.error(f"Script execution timed out after {timeout} seconds")
                return {
                    "status": "timeout",
                    "error": f"Script execution timed out after {timeout} seconds",
                    "duration": timeout
                }
            
        except Exception as e:
            logger.error(f"Error executing script: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "duration": 0
            } 