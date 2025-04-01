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

    def _generate_fallback_script(self, script_name: str, script_type: str) -> Dict[str, Any]:
        """Generate a fallback script when the normal generation fails"""
        try:
            script_path = ""
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if script_type == "python":
                script_path = os.path.join(self.scripts_dir, f'{script_name}_{timestamp}.py')
                script_content = f"""#!/usr/bin/env python3
# Fallback script generated by AI_MAL on {datetime.now().isoformat()}
# The original script generation failed

import sys

def main():
    print("AI_MAL Fallback Script")
    print("----------------------")
    print(f"This script was generated because the original {script_name} script generation failed.")
    print("Usage: python script.py [target]")
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"\\nTarget: {target}")
    
    print("\\nPlease run AI_MAL again to regenerate this script.")

if __name__ == "__main__":
    main()
"""
                with open(script_path, 'w') as f:
                    f.write(script_content)

            elif script_type == "bash":
                script_path = os.path.join(self.scripts_dir, f'{script_name}_{timestamp}.sh')
                script_content = f"""#!/bin/bash
# Fallback script generated by AI_MAL on {datetime.now().isoformat()}
# The original script generation failed

echo "AI_MAL Fallback Script"
echo "----------------------"
echo "This script was generated because the original {script_name} script generation failed."
echo "Usage: bash script.sh [target]"

if [ $# -gt 0 ]; then
    TARGET="$1"
    echo -e "\\nTarget: $TARGET"
fi

echo -e "\\nPlease run AI_MAL again to regenerate this script."
"""
                with open(script_path, 'w') as f:
                    f.write(script_content)

            elif script_type == "ruby":
                script_path = os.path.join(self.scripts_dir, f'{script_name}_{timestamp}.rb')
                script_content = f"""#!/usr/bin/env ruby
# Fallback script generated by AI_MAL on {datetime.now().isoformat()}
# The original script generation failed

puts "AI_MAL Fallback Script"
puts "----------------------"
puts "This script was generated because the original {script_name} script generation failed."
puts "Usage: ruby script.rb [target]"

if ARGV.length > 0
  target = ARGV[0]
  puts "\\nTarget: #{target}"
end

puts "\\nPlease run AI_MAL again to regenerate this script."
"""
                with open(script_path, 'w') as f:
                    f.write(script_content)
                
            else:
                extension = "txt"
                script_path = os.path.join(self.scripts_dir, f'{script_name}_{timestamp}.{extension}')
                with open(script_path, 'w') as f:
                    f.write(f"# Fallback {script_name} script\n# Generated by AI_MAL\n# Script generation failed.")
                
            return {
                "name": script_name,
                "type": script_type,
                "path": script_path,
                "description": f"Fallback {script_name} script (generation error occurred)"
            }
        except Exception as e:
            logger.error(f"Error generating fallback script: {str(e)}")
            return {
                "name": script_name,
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

    def _generate_bash_port_scanner(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Bash port scanner script
        """
        try:
            # Extract target from scan results
            target = scan_results.get("scan_info", {}).get("target", "127.0.0.1")
            
            script_content = f"""#!/bin/bash
# Port scanner for target: {target}
# Generated by AI_MAL on {datetime.now().isoformat()}

if [ -z "$1" ]; then
  TARGET="{target}"
else
  TARGET="$1"
fi

TIMEOUT=1
START_PORT=1
END_PORT=1000

echo "[*] Starting port scan on $TARGET..."
echo "[*] Scanning ports $START_PORT-$END_PORT"

for PORT in $(seq $START_PORT $END_PORT); do
  (echo >/dev/tcp/$TARGET/$PORT) >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    SERVICE=$(grep -w "$PORT/tcp" /etc/services | head -1 | awk '{{print $1}}')
    if [ -z "$SERVICE" ]; then
      SERVICE="unknown"
    fi
    echo "[+] Port $PORT/tcp is open - $SERVICE"
  fi
done 2>/dev/null

echo "[*] Port scan completed"
"""
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            script_path = os.path.join(self.scripts_dir, f'port_scanner_{timestamp}.sh')
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            return {
                "name": "port_scanner",
                "type": "bash",
                "path": script_path,
                "description": f"Port scanning script for {target}"
            }
            
        except Exception as e:
            logger.error(f"Error generating bash port scanner: {str(e)}")
            return self._generate_fallback_script("port_scanner", "bash")

    def _generate_bash_service_enum(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Bash service enumeration script
        """
        try:
            # Extract target from scan results
            target = scan_results.get("scan_info", {}).get("target", "127.0.0.1")
            
            # Extract open ports
            ports = []
            for host in scan_results.get("hosts", []):
                for port_info in host.get("ports", []):
                    if port_info.get("state") == "open":
                        ports.append(str(port_info.get("port")))
            
            port_list = " ".join(ports) if ports else "22 80 443"
            
            script_content = f"""#!/bin/bash
# Service enumeration script for target: {target}
# Generated by AI_MAL on {datetime.now().isoformat()}

if [ -z "$1" ]; then
  TARGET="{target}"
else
  TARGET="$1"
fi

if [ -z "$2" ]; then
  PORTS="{port_list}"
else
  PORTS="$2"
fi

echo "[*] Starting service enumeration on $TARGET"
echo "[*] Target ports: $PORTS"

for PORT in $PORTS; do
  echo "[*] Checking port $PORT..."
  
  # Try banner grabbing with netcat
  BANNER=$(timeout 3 nc -w 3 -zv $TARGET $PORT 2>&1)
  STATUS=$?
  
  if [ $STATUS -eq 0 ]; then
    echo "[+] Port $PORT is open"
    
    # Get service from /etc/services
    SERVICE=$(grep -w "$PORT/tcp" /etc/services | head -1 | awk '{{print $1}}')
    if [ -z "$SERVICE" ]; then
      SERVICE="unknown"
    fi
    
    echo "    Service: $SERVICE"
    
    # Try to get banner
    if [[ "$BANNER" == *"open"* ]]; then
      echo "    Banner: $BANNER"
    fi
    
    # HTTP specific checks
    if [ "$PORT" == "80" ] || [ "$PORT" == "443" ] || [ "$SERVICE" == "http" ] || [ "$SERVICE" == "https" ]; then
      PROTOCOL="http"
      if [ "$PORT" == "443" ] || [ "$SERVICE" == "https" ]; then
        PROTOCOL="https"
      fi
      
      echo "    Checking HTTP headers..."
      timeout 5 curl -s -I "$PROTOCOL://$TARGET:$PORT" | grep -E "Server:|X-Powered-By:" || echo "    No server headers found"
    fi
  else
    echo "[-] Port $PORT is closed or filtered"
  fi
done

echo "[*] Enumeration completed"
"""
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            script_path = os.path.join(self.scripts_dir, f'service_enum_{timestamp}.sh')
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            return {
                "name": "service_enum",
                "type": "bash",
                "path": script_path,
                "description": f"Service enumeration script for {target}"
            }
            
        except Exception as e:
            logger.error(f"Error generating bash service enumerator: {str(e)}")
            return self._generate_fallback_script("service_enum", "bash")

    def _generate_bash_vuln_scanner(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Bash vulnerability scanner script
        """
        try:
            # Extract target from scan results
            target = scan_results.get("scan_info", {}).get("target", "127.0.0.1")
            
            # Extract services
            services = []
            for host in scan_results.get("hosts", []):
                for port_info in host.get("ports", []):
                    if port_info.get("state") == "open":
                        port = port_info.get("port")
                        service = port_info.get("service", "unknown")
                        services.append(f"{port}:{service}")
            
            services_str = " ".join(services) if services else "no open ports found"
            
            script_content = f"""#!/bin/bash
# Vulnerability scanner for target: {target}
# Open services: {services_str}
# Generated by AI_MAL on {datetime.now().isoformat()}

if [ -z "$1" ]; then
  TARGET="{target}"
else
  TARGET="$1"
fi

if [ -z "$2" ]; then
  PORTS_SERVICES="{services_str}"
else
  PORTS_SERVICES="$2"
fi

echo "[*] Starting vulnerability scan on $TARGET"
echo "[*] Target services: $PORTS_SERVICES"

# Function to check for vulnerabilities
check_vulns() {{
  local PORT=$1
  local SERVICE=$2
  
  echo "[*] Checking vulnerabilities for $SERVICE on port $PORT"
  
  # Web checks
  if [[ "$SERVICE" == *"http"* ]] || [ "$PORT" == "80" ] || [ "$PORT" == "443" ] || [ "$PORT" == "8080" ]; then
    PROTOCOL="http"
    if [ "$PORT" == "443" ] || [[ "$SERVICE" == *"https"* ]]; then
      PROTOCOL="https"
    fi
    
    echo "    Checking common web vulnerabilities..."
    
    # Check for robots.txt
    STATUS=$(curl -s -o /dev/null -w "%{{http_code}}" "$PROTOCOL://$TARGET:$PORT/robots.txt")
    if [ "$STATUS" != "404" ]; then
      echo "    [VULN] Found robots.txt ($STATUS)"
    fi
    
    # Check for admin panel
    STATUS=$(curl -s -o /dev/null -w "%{{http_code}}" "$PROTOCOL://$TARGET:$PORT/admin")
    if [ "$STATUS" != "404" ]; then
      echo "    [VULN] Found admin panel ($STATUS)"
    fi
    
    # Check for phpMyAdmin
    STATUS=$(curl -s -o /dev/null -w "%{{http_code}}" "$PROTOCOL://$TARGET:$PORT/phpmyadmin")
    if [ "$STATUS" != "404" ]; then
      echo "    [VULN] Found phpMyAdmin ($STATUS)"
    fi
  fi
  
  # FTP checks
  if [[ "$SERVICE" == *"ftp"* ]] || [ "$PORT" == "21" ]; then
    echo "    Checking FTP vulnerabilities..."
    
    # Try anonymous login
    ANON_FTP=$(timeout 5 bash -c "echo -e 'anonymous\nanonymous\nquit' | ftp -n $TARGET $PORT 2>&1")
    if [[ "$ANON_FTP" == *"230"* ]]; then
      echo "    [VULN] Anonymous FTP login allowed"
    fi
  fi
  
  # SSH checks
  if [[ "$SERVICE" == *"ssh"* ]] || [ "$PORT" == "22" ]; then
    echo "    Checking SSH vulnerabilities..."
    
    # Get SSH version
    SSH_VERSION=$(timeout 5 nc -w 5 $TARGET $PORT 2>&1 | grep -i ssh)
    if [[ "$SSH_VERSION" == *"SSH-1"* ]]; then
      echo "    [VULN] Old SSH version detected: $SSH_VERSION"
    fi
  fi
}}

# Parse port:service pairs
for PORT_SERVICE in $PORTS_SERVICES; do
  if [[ "$PORT_SERVICE" == *":"* ]]; then
    PORT=$(echo "$PORT_SERVICE" | cut -d':' -f1)
    SERVICE=$(echo "$PORT_SERVICE" | cut -d':' -f2)
    check_vulns "$PORT" "$SERVICE"
  else
    # If only port is provided
    PORT="$PORT_SERVICE"
    SERVICE="unknown"
    check_vulns "$PORT" "$SERVICE"
  fi
done

echo "[*] Vulnerability scan completed"
"""
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            script_path = os.path.join(self.scripts_dir, f'vuln_scanner_{timestamp}.sh')
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            return {
                "name": "vuln_scanner",
                "type": "bash",
                "path": script_path,
                "description": f"Vulnerability scanning script for {target}"
            }
            
        except Exception as e:
            logger.error(f"Error generating bash vulnerability scanner: {str(e)}")
            return self._generate_fallback_script("vuln_scanner", "bash")

    def _generate_ruby_port_scanner(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Ruby port scanner script
        """
        try:
            # Extract target from scan results
            target = scan_results.get("scan_info", {}).get("target", "127.0.0.1")
            
            script_content = f"""#!/usr/bin/env ruby
# Port scanner for target: {target}
# Generated by AI_MAL on {datetime.now().isoformat()}

require 'socket'
require 'timeout'

# Target setup
target = ARGV[0] || '{target}'
start_port = 1
end_port = 1000

# Banner
puts "[*] Starting port scan on #{target}"
puts "[*] Scanning ports #{start_port}-#{end_port}"

# Function to scan a port
def port_open?(ip, port, timeout=1)
  begin
    Timeout::timeout(timeout) do
      begin
        s = TCPSocket.new(ip, port)
        s.close
        return true
      rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
        return false
      end
    end
  rescue Timeout::Error
    return false
  end
end

# Port scan
open_ports = []
(start_port..end_port).each do |port|
  if port_open?(target, port)
    begin
      service = Socket.getservbyport(port)
    rescue
      service = "unknown"
    end
    
    puts "[+] Port #{port}/tcp is open - #{service}"
    open_ports << port
  end
end

puts "[*] Port scan completed, found #{open_ports.length} open ports"
"""
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            script_path = os.path.join(self.scripts_dir, f'port_scanner_{timestamp}.rb')
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            return {
                "name": "port_scanner",
                "type": "ruby",
                "path": script_path,
                "description": f"Port scanning script for {target}"
            }
            
        except Exception as e:
            logger.error(f"Error generating ruby port scanner: {str(e)}")
            return self._generate_fallback_script("port_scanner", "ruby")

    def _generate_ruby_service_enum(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Ruby service enumeration script
        """
        try:
            # Extract target from scan results
            target = scan_results.get("scan_info", {}).get("target", "127.0.0.1")
            
            # Extract ports discovered in scan
            ports = []
            for host in scan_results.get("hosts", []):
                for port_info in host.get("ports", []):
                    if port_info.get("state") == "open":
                        ports.append(str(port_info.get("port")))
            
            port_list = ",".join(ports) if ports else "22,80,443"
            
            script_content = f"""#!/usr/bin/env ruby
# Service enumeration script for target: {target}
# Generated by AI_MAL on {datetime.now().isoformat()}

require 'socket'
require 'timeout'

# Target setup
target = ARGV[0] || '{target}'
ports = ARGV[1] ? ARGV[1].split(',') : '{port_list}'.split(',')

# Banner
puts "[*] Starting service enumeration on #{target}"
puts "[*] Target ports: #{ports.join(', ')}"

# Function to get service banner
def get_banner(ip, port, timeout=3)
  begin
    Timeout::timeout(timeout) do
      begin
        s = TCPSocket.new(ip, port)
        banner = s.recv(1024).strip
        s.close
        return banner
      rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
        return nil
      end
    end
  rescue Timeout::Error
    return nil
  end
end

# Enumerate services
ports.each do |port|
  port = port.to_i
  puts "[*] Checking port #{port}..."
  
  begin
    # Try to get service name
    begin
      service = Socket.getservbyport(port)
    rescue
      service = "unknown"
    end
    
    # Try to connect and check if port is open
    begin
      Timeout::timeout(2) do
        s = TCPSocket.new(target, port)
        puts "[+] Port #{port} is open - #{service}"
        s.close
        
        # Try to get banner
        banner = get_banner(target, port)
        if banner && !banner.empty?
          puts "    Banner: #{banner}"
        end
        
        # HTTP specific checks
        if [80, 443, 8080, 8443].include?(port) || service == 'http' || service == 'https'
          protocol = (port == 443 || service == 'https') ? 'https' : 'http'
          puts "    HTTP service detected - You can investigate further with a web browser"
        end
      end
    rescue Timeout::Error, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
      puts "[-] Port #{port} is closed or filtered"
    end
  rescue => e
    puts "    Error checking port #{port}: #{e.message}"
  end
end

puts "[*] Enumeration completed"
"""
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            script_path = os.path.join(self.scripts_dir, f'service_enum_{timestamp}.rb')
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            return {
                "name": "service_enum",
                "type": "ruby",
                "path": script_path,
                "description": f"Service enumeration script for {target}"
            }
            
        except Exception as e:
            logger.error(f"Error generating ruby service enumerator: {str(e)}")
            return self._generate_fallback_script("service_enum", "ruby")

    def _generate_ruby_vuln_scanner(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate Ruby vulnerability scanner script
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
            
            services_str = " ".join(services) if services else "no open ports found"
            
            script_content = f"""#!/usr/bin/env ruby
# Vulnerability scanner for target: {target}
# Open services: {services_str}
# Generated by AI_MAL on {datetime.now().isoformat()}

require 'socket'
require 'timeout'
require 'net/http'
require 'uri'
require 'net/ftp'

# Target setup
target = ARGV[0] || '{target}'
port_services = ARGV[1] ? ARGV[1].split(',') : '{','.join(services)}'.split(',')

# Banner
puts "[*] Starting vulnerability scan on #{target}"
puts "[*] Target services: #{port_services.join(', ')}"

# Function to check HTTP path
def check_http_path(ip, port, path, protocol='http')
  begin
    uri = URI("#{protocol}://#{ip}:#{port}#{path}")
    response = Net::HTTP.get_response(uri)
    if response.code != '404'
      return true, "Found: #{path} (Status: #{response.code})"
    end
  rescue => e
    puts "    HTTP Error: #{e.message}" if $DEBUG
  end
  return false, nil
end

# Function to check FTP anonymous access
def check_ftp_anonymous(ip, port)
  begin
    ftp = Net::FTP.new
    ftp.connect(ip, port)
    ftp.login('anonymous', 'anonymous@example.com')
    ftp.close
    return true, "Anonymous FTP access allowed"
  rescue => e
    puts "    FTP Error: #{e.message}" if $DEBUG
  end
  return false, nil
end

# Function to check SSH version
def check_ssh_version(ip, port)
  begin
    Timeout::timeout(5) do
      s = TCPSocket.new(ip, port)
      banner = s.recv(1024).strip
      s.close
      
      if banner.include?('SSH-1.') || banner.include?('SSH-1.99')
        return true, "Vulnerable SSH version: #{banner}"
      end
    end
  rescue => e
    puts "    SSH Error: #{e.message}" if $DEBUG
  end
  return false, nil
end

# Check vulnerabilities for a service
def check_vulnerabilities(ip, port, service)
  results = []
  
  puts "[*] Checking vulnerabilities for #{service} on port #{port}"
  
  # Web checks
  if ['http', 'https', 'www'].include?(service.downcase) || [80, 443, 8080, 8443].include?(port.to_i)
    protocol = (port.to_i == 443 || service.downcase == 'https') ? 'https' : 'http'
    
    puts "    Checking common web vulnerabilities..."
    
    # Common web paths to check
    [
      ['/robots.txt', 'Robots file'],
      ['/admin', 'Admin panel'],
      ['/wp-login.php', 'WordPress login'],
      ['/phpmyadmin', 'phpMyAdmin panel'],
      ['/manager/html', 'Tomcat Manager']
    ].each do |path, desc|
      found, details = check_http_path(ip, port, path, protocol)
      if found
        puts "    [VULN] #{details}"
        results << details
      end
    end
  end
  
  # FTP checks
  if service.downcase == 'ftp' || port.to_i == 21
    puts "    Checking FTP vulnerabilities..."
    found, details = check_ftp_anonymous(ip, port)
    if found
      puts "    [VULN] #{details}"
      results << details
    end
  end
  
  # SSH checks
  if service.downcase == 'ssh' || port.to_i == 22
    puts "    Checking SSH vulnerabilities..."
    found, details = check_ssh_version(ip, port)
    if found
      puts "    [VULN] #{details}"
      results << details
    end
  end
  
  return results
end

# Main scanning logic
vulnerabilities = []

port_services.each do |port_service|
  if port_service.include?(':')
    port, service = port_service.split(':', 2)
  else
    port = port_service
    service = 'unknown'
  end
  
  results = check_vulnerabilities(target, port, service)
  vulnerabilities.concat(results) if !results.empty?
end

puts "[*] Vulnerability scan completed"
puts "[*] Found #{vulnerabilities.length} potential vulnerabilities"
"""
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            script_path = os.path.join(self.scripts_dir, f'vuln_scanner_{timestamp}.rb')
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            return {
                "name": "vuln_scanner",
                "type": "ruby",
                "path": script_path,
                "description": f"Vulnerability scanning script for {target}"
            }
            
        except Exception as e:
            logger.error(f"Error generating ruby vulnerability scanner: {str(e)}")
            return self._generate_fallback_script("vuln_scanner", "ruby") 