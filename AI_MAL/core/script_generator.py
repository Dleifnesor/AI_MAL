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
        """Initialize the script generator"""
        # Get scripts directory from environment variable or use default
        self.scripts_dir = os.getenv('GENERATED_SCRIPTS_DIR', 'generated_scripts')
        
        # Ensure scripts_dir is an absolute path if possible
        if not os.path.isabs(self.scripts_dir) and 'INSTALL_DIR' in os.environ:
            self.scripts_dir = os.path.join(os.environ['INSTALL_DIR'], self.scripts_dir)
        
        # Create scripts directory if it doesn't exist
        try:
            os.makedirs(self.scripts_dir, exist_ok=True)
            logger.info(f"Using scripts directory: {self.scripts_dir}")
            
            # Make sure the directory is writable
            if not os.access(self.scripts_dir, os.W_OK):
                logger.warning(f"Scripts directory is not writable: {self.scripts_dir}")
                # Try to fix permissions
                try:
                    os.chmod(self.scripts_dir, 0o755)
                    logger.info(f"Fixed permissions on scripts directory: {self.scripts_dir}")
                except Exception as perm_error:
                    logger.error(f"Failed to fix permissions: {str(perm_error)}")
        except Exception as e:
            logger.warning(f"Failed to create scripts directory: {str(e)}")
            # Fall back to current directory/generated_scripts if we can't create the configured one
            fallback_dir = os.path.join(os.getcwd(), 'generated_scripts')
            try:
                os.makedirs(fallback_dir, exist_ok=True)
                self.scripts_dir = fallback_dir
                logger.info(f"Using fallback scripts directory: {self.scripts_dir}")
            except Exception as fallback_error:
                logger.error(f"Failed to create fallback scripts directory: {str(fallback_error)}")
                # Last resort, just use the current directory
                self.scripts_dir = os.getcwd()
                logger.warning(f"Using current directory for scripts: {self.scripts_dir}")
        
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
    ) -> Dict[str, Dict[str, Any]]:
        """
        Generate custom exploitation scripts based on scan results
        Returns a dictionary where keys are script paths and values are script details
        """
        try:
            print("\n" + "="*80)
            print(f"Generating {script_type.upper()} scripts for target: {scan_results.get('scan_info', {}).get('target', 'unknown')}")
            print("="*80)
            
            scripts = []
            
            if script_type == 'python':
                scripts.extend(await self._generate_python_scripts(scan_results))
            elif script_type == 'bash':
                scripts.extend(await self._generate_bash_scripts(scan_results))
            elif script_type == 'ruby':
                scripts.extend(await self._generate_ruby_scripts(scan_results))
            
            # Display a summary of the generated scripts
            print("\n" + "-"*40)
            print(f"Generated {len(scripts)} {script_type.upper()} scripts:")
            print("-"*40)
            for script in scripts:
                print(f"- {script['name']}: {script['description']}")
                print(f"  Path: {script['path']}")
                
                # Display script contents with syntax highlighting if possible
                try:
                    from pygments import highlight
                    from pygments.lexers import get_lexer_for_filename
                    from pygments.formatters import TerminalFormatter
                    
                    with open(script['path'], 'r') as f:
                        content = f.read()
                    
                    lexer = get_lexer_for_filename(script['path'])
                    highlighted = highlight(content, lexer, TerminalFormatter())
                    
                    print("\nScript Contents:")
                    print(highlighted)
                except ImportError:
                    # Fallback if pygments is not available
                    with open(script['path'], 'r') as f:
                        content = f.read()
                    
                    print("\nScript Contents:")
                    print(content[:500] + "..." if len(content) > 500 else content)
                except Exception as e:
                    logger.error(f"Error displaying script contents: {str(e)}")
                
                print("-"*40)
            
            # Convert the list of scripts to a dictionary indexed by path
            script_dict = {script['path']: script for script in scripts}
            return script_dict
            
        except Exception as e:
            logger.error(f"Error generating scripts: {str(e)}")
            print(f"Error generating scripts: {str(e)}")
            return {}

    async def execute_scripts(self, scripts: Dict[str, Dict[str, Any]], script_type: str = None) -> List[Dict[str, Any]]:
        """
        Execute generated scripts
        
        Args:
            scripts: Dictionary of scripts (path -> script details) from generate_scripts
            script_type: Optional script type filter (python, bash, ruby)
            
        Returns:
            List of execution results
        """
        try:
            print("\n" + "="*80)
            print("Executing Generated Scripts")
            print("="*80)
            
            results = []
            
            # Convert dictionary to list of scripts for processing
            script_list = list(scripts.values())
            
            # Filter by script type if specified
            if script_type:
                script_list = [s for s in script_list if s.get('type') == script_type]
            
            for script in script_list:
                # Skip scripts with invalid paths
                script_path = script.get('path')
                if not script_path or not os.path.exists(script_path):
                    logger.warning(f"Script path not found: {script_path}")
                    print(f"⚠️  Script path not found: {script_path}")
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
                print("\n" + "-"*40)
                print(f"🚀 Executing script: {script['name']} ({script['type']})")
                print(f"📄 Path: {script['path']}")
                print("-"*40)
                
                # Display animated "Running..." message
                import threading
                import time
                
                running = True
                
                def animation():
                    animation_chars = "|/-\\"
                    idx = 0
                    while running:
                        print(f"\rRunning {animation_chars[idx % len(animation_chars)]}", end="")
                        idx += 1
                        time.sleep(0.1)
                
                # Start animation in a separate thread
                animation_thread = threading.Thread(target=animation)
                animation_thread.daemon = True
                animation_thread.start()
                
                try:
                    # Execute script and capture result
                    result = await self._execute_script(script)
                    
                    # Stop animation
                    running = False
                    animation_thread.join(0.5)
                    
                    # Clear the animation line
                    print("\r" + " " * 20 + "\r", end="")
                    
                    # Print result status
                    status = result.get('status', 'unknown')
                    if status == 'success':
                        print(f"✅ Script executed successfully (took {result.get('duration', 0):.2f} seconds)")
                    else:
                        print(f"❌ Script execution failed: {status}")
                        if 'error' in result:
                            print(f"Error: {result['error']}")
                    
                    # Print script output
                    if 'output' in result and result['output']:
                        print("\nScript Output:")
                        print("-"*40)
                        output = result['output']
                        # Limit output to prevent flooding the terminal
                        if len(output) > 2000:
                            print(output[:2000] + "...\n(output truncated)")
                        else:
                            print(output)
                    
                    results.append({
                        "script": script,
                        "result": result
                    })
                    
                except Exception as e:
                    # Stop animation
                    running = False
                    animation_thread.join(0.5)
                    
                    print(f"\r❌ Error executing script: {str(e)}")
                    results.append({
                        "script": script,
                        "result": {
                            "status": "error",
                            "error": str(e),
                            "duration": 0
                        }
                    })
            
            # Print summary of all results
            print("\n" + "="*40)
            print("Script Execution Summary")
            print("="*40)
            for result in results:
                script_name = result['script']['name']
                status = result['result']['status']
                duration = result.get('result', {}).get('duration', 0)
                
                if status == 'success':
                    print(f"✅ {script_name}: Success ({duration:.2f}s)")
                else:
                    print(f"❌ {script_name}: {status.capitalize()}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error executing scripts: {str(e)}")
            print(f"Error executing scripts: {str(e)}")
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

def get_service_info(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))
        
        # Try to get banner
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        return {
            'port': port,
            'service': socket.getservbyport(port),
            'banner': banner
        }
    except Exception as e:
        return {
            'port': port,
            'service': 'unknown',
            'error': str(e)
        }

def enumerate_services(target, ports, threads=5):
    print(f"[*] Starting service enumeration on {target}")
    start_time = datetime.now()
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for port in ports:
            futures.append(executor.submit(get_service_info, target, port))
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            if 'error' not in result:
                print(f"[+] Port {result['port']}: {result['service']}")
                if result.get('banner'):
                    print(f"    Banner: {result['banner']}")
            else:
                print(f"[-] Port {result['port']}: Error - {result['error']}")
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print(f"\n[*] Enumeration completed in {duration:.2f} seconds")
    print(f"[*] Found {len([r for r in results if 'error' not in r])} services on {target}")
    
    return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Service enumeration script')
    parser.add_argument('target', nargs='?', default='{target}', help='Target IP address')
    parser.add_argument('-p', '--ports', default='{port_list}', 
                        help='Comma-separated list of ports to scan')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads to use')
    
    args = parser.parse_args()
    
    # Parse ports
    try:
        ports = [int(p) for p in args.ports.split(',')]
    except ValueError:
        print("Invalid port list. Use comma-separated numbers (e.g. 22,80,443)")
        sys.exit(1)
    
    enumerate_services(args.target, ports, args.threads)
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

    def _generate_fallback_script(self, script_name: str, script_type: str) -> str:
        """Generate a simple fallback script when primary script generation fails.
        
        Args:
            script_name: Name of the script (port_scanner, vuln_scanner, etc.)
            script_type: Type of script to generate (python, bash, ruby)
            
        Returns:
            A string containing the script content
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if script_type.lower() == "python":
            return f"""#!/usr/bin/env python3
# Fallback {script_name} script
# Generated by AI_MAL on {timestamp}

import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    logger.info("This is a fallback script. The original script generation failed.")
    logger.info("Usage: {script_name}.py [target]")
    if len(sys.argv) > 1:
        target = sys.argv[1]
        logger.info(f"Target: {{target}}")
    else:
        logger.info("No target specified")

if __name__ == "__main__":
    main()
"""
        elif script_type.lower() == "bash":
            return f"""#!/bin/bash
# Fallback {script_name} script
# Generated by AI_MAL on {timestamp}

echo "This is a fallback script. The original script generation failed."
echo "Usage: {script_name}.sh [target]"

if [ $# -gt 0 ]; then
    echo "Target: $1"
else
    echo "No target specified"
fi
"""
        elif script_type.lower() == "ruby":
            return f"""#!/usr/bin/env ruby
# Fallback {script_name} script
# Generated by AI_MAL on {timestamp}

puts "This is a fallback script. The original script generation failed."
puts "Usage: ruby {script_name}.rb [target]"

if ARGV.length > 0
  puts "Target: #{ARGV[0]}"
else
  puts "No target specified"
end
"""
        else:
            # Default to text file if unknown script type
            return f"""# Fallback {script_name} script
# Generated by AI_MAL on {timestamp}
#
# This is a fallback text file. The original script generation failed.
"""

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
                
                # Verify script exists and has content
                if not os.path.exists(script['path']):
                    logger.error(f"Script file does not exist: {script['path']}")
                    return {
                        "status": "error",
                        "error": f"Script file not found: {script['path']}",
                        "duration": 0
                    }
                
                # Check file size to make sure it's not empty
                file_size = os.path.getsize(script['path'])
                if file_size == 0:
                    logger.error(f"Script file is empty: {script['path']}")
                    return {
                        "status": "error",
                        "error": "Script file is empty",
                        "duration": 0
                    }
                
                # Ensure script is executable
                try:
                    os.chmod(script['path'], 0o755)
                    logger.debug(f"Set executable permissions on {script['path']}")
                except Exception as e:
                    logger.warning(f"Failed to set executable permissions on {script['path']}: {str(e)}")
                    # Try with sudo
                    try:
                        subprocess.run(['sudo', 'chmod', '+x', script['path']], check=True)
                        logger.debug(f"Set executable permissions with sudo on {script['path']}")
                    except Exception as sudo_e:
                        logger.error(f"Failed to set executable permissions with sudo: {str(sudo_e)}")
                
                # Verify script has executable permissions
                if not os.access(script['path'], os.X_OK):
                    logger.warning(f"Script still not executable after chmod: {script['path']}")
                    # Continue anyway, we're using interpreters
                
                # Log more detailed info about the script execution
                logger.info(f"Executing script: {script['name']} ({script['type']}) at {script['path']}")
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                stdout_text = stdout.decode('utf-8', errors='replace')
                stderr_text = stderr.decode('utf-8', errors='replace')
                
                # Detailed logging of output
                logger.debug(f"Script stdout: {stdout_text}")
                if stderr_text:
                    logger.debug(f"Script stderr: {stderr_text}")
                
                # Log script exit code
                exit_code = process.returncode
                logger.info(f"Script exit code: {exit_code}")
                
                if exit_code != 0:
                    logger.warning(f"Script returned non-zero exit code: {exit_code}")
                
                return {
                    "status": "success" if exit_code == 0 else "error",
                    "exit_code": exit_code,
                    "output": stdout_text,
                    "error": stderr_text if stderr_text else None,
                    "duration": duration
                }
                
            except asyncio.TimeoutError:
                logger.error(f"Script execution timed out after {timeout} seconds: {script['path']}")
                return {
                    "status": "timeout",
                    "error": f"Execution timed out after {timeout} seconds",
                    "duration": timeout
                }
            
        except Exception as e:
            logger.error(f"Error executing script {script.get('path', 'unknown')}: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
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
echo "[*] Scanning ports: $PORTS"

for PORT in $PORTS; do
  echo "[*] Checking port $PORT..."
  
  # Try to get service name
  SERVICE=$(grep -w "$PORT/tcp" /etc/services | head -1 | awk '{{print $1}}')
  if [ -z "$SERVICE" ]; then
    SERVICE="unknown"
  fi
  
  # Try to get banner
  BANNER=$(timeout 2 bash -c "echo '' | nc -w 2 $TARGET $PORT 2>/dev/null")
  
  if [ $? -eq 0 ]; then
    echo "[+] Port $PORT/tcp is open - $SERVICE"
    if [ ! -z "$BANNER" ]; then
      echo "    Banner: $BANNER"
    fi
  else
    echo "[-] Port $PORT/tcp: Error connecting"
  fi
done

echo "[*] Service enumeration completed"
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
    
    # Check for common admin paths
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
            
            script_content = """#!/usr/bin/env ruby
# Port scanner for target: """ + target + """
# Generated by AI_MAL on """ + datetime.now().isoformat() + """

require 'socket'
require 'timeout'

class PortScanner
  def initialize(target, start_port, end_port)
    @target = target
    @start_port = start_port
    @end_port = end_port
    @open_ports = []
  end
  
  def scan
    puts "[*] Starting port scan on \#{@target}..."
    puts "[*] Scanning ports \#{@start_port}-\#{@end_port}"
    
    start_time = Time.now
    
    (@start_port..@end_port).each do |port|
  begin
    Timeout.timeout(1) do
          socket = TCPSocket.new(@target, port)
      socket.close
          service = get_service_name(port)
          @open_ports << { port: port, service: service }
          puts "[+] Port \#{port}/tcp is open - \#{service}"
    end
  rescue Timeout::Error
        # Port is closed or filtered
      rescue Errno::ECONNREFUSED
        # Port is closed
  rescue => e
        puts "[!] Error scanning port \#{port}: \#{e.message}"
  end
end
    
    end_time = Time.now
    duration = end_time - start_time
    
    puts "\n[*] Scan completed in \#{duration.round(2)} seconds"
    puts "[*] Found \#{@open_ports.size} open ports on \#{@target}"
    
    @open_ports
  end
  
  private
  
  def get_service_name(port)
    begin
      service = Socket.getservbyport(port)
    rescue
      service = "unknown"
    end
    service
  end
end

# Main execution
if ARGV.length < 1
  puts "Usage: \#{File.basename($0)} <target> [start_port] [end_port]"
  puts "Example: \#{File.basename($0)} 192.168.1.1 1 1000"
  exit 1
end

target = ARGV[0]
start_port = (ARGV[1] || 1).to_i
end_port = (ARGV[2] || 1000).to_i

scanner = PortScanner.new(target, start_port, end_port)
scanner.scan
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
            logger.error(f"Error generating Ruby port scanner: {str(e)}")
            return self._generate_fallback_script("port_scanner", "ruby")

    def _generate_ruby_service_enum(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Ruby service enumeration script."""
        try:
            # Extract target from scan results
            target = scan_results.get("scan_info", {}).get("target", "127.0.0.1")
            
            # Extract open ports
            ports = []
            for host in scan_results.get("hosts", []):
                for port_info in host.get("ports", []):
                    if port_info.get("state") == "open":
                        ports.append(str(port_info.get("port")))
            
            port_list = ",".join(ports) if ports else "22,80,443"
            
            script_content = """#!/usr/bin/env ruby
# Service enumeration script for target: """ + target + """
# Generated by AI_MAL on """ + datetime.now().isoformat() + """

require 'socket'
require 'timeout'

class ServiceEnumerator
  def initialize(target, ports)
    @target = target
    @ports = ports
    @results = []
  end

  def enumerate
    @ports.each do |port|
      begin
        Timeout.timeout(2) do
          socket = TCPSocket.new(@target, port)
          socket.close
          @results << {port: port, status: 'open'}
        end
      rescue Timeout::Error
        @results << {port: port, status: 'timeout'}
      rescue => e
        @results << {port: port, status: 'error', error: e.message}
      end
    end
    @results
  end
end

# Main execution
if ARGV.length != 2
  puts "Usage: \#{File.basename($0)} <target> <ports>"
  puts "Example: \#{File.basename($0)} 192.168.1.1 80,443,8080"
  exit 1
end

target = ARGV[0]
ports = ARGV[1].split(',').map(&:to_i)

puts "Enumerating services on \#{target}..."
enumerator = ServiceEnumerator.new(target, ports)
results = enumerator.enumerate

results.each do |result|
  puts "Port \#{result[:port]}: \#{result[:status]}"
  puts "Error: \#{result[:error]}" if result[:error]
end
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
            logger.error(f"Error generating Ruby service enumeration: {str(e)}")
            return self._generate_fallback_script("service_enum", "ruby")

    def _generate_ruby_vuln_scanner(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Ruby vulnerability scanner script."""
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
            
            services_str = ", ".join(services) if services else "no open ports found"
            
            script_content = """#!/usr/bin/env ruby
# Vulnerability scanner for target: """ + target + """
# Open services: """ + services_str + """
# Generated by AI_MAL on """ + datetime.now().isoformat() + """

require 'socket'
require 'timeout'
require 'net/http'
require 'uri'

class VulnerabilityScanner
  def initialize(target, ports_services)
    @target = target
    @ports_services = parse_ports_services(ports_services)
    @vulnerabilities = []
  end
  
  def parse_ports_services(ports_services)
    result = []
    ports_services.split(',').each do |port_service|
      if port_service.include?(':')
        port, service = port_service.split(':', 2)
        result << {port: port.strip.to_i, service: service.strip.downcase}
      else
        result << {port: port_service.strip.to_i, service: 'unknown'}
      end
    end
    result
  end
  
  def scan
    @ports_services.each do |ps|
      port = ps[:port]
      service = ps[:service]
      
      puts "Checking \#{service} on port \#{port}..."
      
      case service
      when 'http', 'https', 'www'
        check_web_vulnerabilities(port, service)
      when 'ftp'
        check_ftp_vulnerabilities(port)
      when 'ssh'
        check_ssh_vulnerabilities(port)
      when 'smtp'
        check_smtp_vulnerabilities(port)
      else
        # Try to determine service by port
        case port
        when 80, 443, 8080, 8443
          check_web_vulnerabilities(port, (port == 443 || port == 8443) ? 'https' : 'http')
        when 21
          check_ftp_vulnerabilities(port)
        when 22
          check_ssh_vulnerabilities(port)
        when 25
          check_smtp_vulnerabilities(port)
        end
      end
    end
    
    @vulnerabilities
  end
  
  def check_web_vulnerabilities(port, service)
    protocol = (service == 'https' || port == 443 || port == 8443) ? 'https' : 'http'
  
    begin
      # Check for robots.txt
      uri = URI.parse("\#{protocol}://\#{@target}:\#{port}/robots.txt")
      response = Net::HTTP.get_response(uri)
      
      if response.code != '404'
        @vulnerabilities << {
          port: port,
          service: service,
          vulnerability: 'robots.txt found',
          details: "Found robots.txt with status code \#{response.code}"
        }
      end
      
      # Check for common admin paths
      ['/admin', '/administrator', '/wp-admin', '/phpmyadmin'].each do |path|
        uri = URI.parse("\#{protocol}://\#{@target}:\#{port}\#{path}")
        response = Net::HTTP.get_response(uri)
        
        if response.code != '404'
          @vulnerabilities << {
            port: port,
            service: service,
            vulnerability: "\#{path} found",
            details: "Found \#{path} with status code \#{response.code}"
          }
        end
      end
    rescue => e
      puts "Error checking web vulnerabilities: \#{e.message}"
    end
  end
  
  def check_ftp_vulnerabilities(port)
    begin
      # Check for anonymous login
      Timeout.timeout(5) do
        socket = TCPSocket.new(@target, port)
        banner = socket.gets
        
        socket.puts "USER anonymous"
        response1 = socket.gets
        
        socket.puts "PASS anonymous@example.com"
        response2 = socket.gets
        
        if response2.start_with?('230')
          @vulnerabilities << {
            port: port,
            service: 'ftp',
            vulnerability: 'Anonymous FTP access',
            details: "Anonymous FTP login allowed: \#{response2.strip}"
          }
        end
        
        socket.close
      end
    rescue => e
      puts "Error checking FTP vulnerabilities: \#{e.message}"
    end
  end
  
  def check_ssh_vulnerabilities(port)
    begin
      Timeout.timeout(5) do
        socket = TCPSocket.new(@target, port)
        banner = socket.gets
        socket.close
        
        if banner.include?('SSH-1') || banner.include?('SSH-2.0-')
          @vulnerabilities << {
            port: port,
            service: 'ssh',
            vulnerability: 'SSH version information disclosure',
            details: "SSH banner: \#{banner.strip}"
          }
        end
      end
    rescue => e
      puts "Error checking SSH vulnerabilities: \#{e.message}"
    end
  end
  
  def check_smtp_vulnerabilities(port)
    begin
      Timeout.timeout(5) do
        socket = TCPSocket.new(@target, port)
        banner = socket.gets
        
        # Check VRFY command
        socket.puts "VRFY root"
        response = socket.gets
        
        if !response.start_with?('5')
          @vulnerabilities << {
            port: port,
            service: 'smtp',
            vulnerability: 'SMTP VRFY command enabled',
            details: "VRFY command response: \#{response.strip}"
          }
        end
        
        socket.close
      end
    rescue => e
      puts "Error checking SMTP vulnerabilities: \#{e.message}"
    end
  end
end

# Main execution
if ARGV.length < 1
  puts "Usage: \#{File.basename($0)} <target> [ports_services]"
  puts "Example: \#{File.basename($0)} 192.168.1.1 '80:http,443:https,22:ssh'"
  exit 1
end

target = ARGV[0]
ports_services = ARGV[1] || '""" + services_str + """'

puts "Starting vulnerability scan for \#{target}..."
scanner = VulnerabilityScanner.new(target, ports_services)
vulnerabilities = scanner.scan

puts "\nScan Results:"
puts "=============="

if vulnerabilities.empty?
  puts "No vulnerabilities found."
else
  puts "Found \#{vulnerabilities.size} potential vulnerabilities:"
  vulnerabilities.each_with_index do |vuln, i|
    puts "\n\#{i+1}. \#{vuln[:vulnerability]}"
    puts "   Port: \#{vuln[:port]} (\#{vuln[:service]})"
    puts "   Details: \#{vuln[:details]}"
  end
end
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
            logger.error(f"Error generating Ruby vulnerability scanner: {str(e)}")
            return self._generate_fallback_script("vuln_scanner", "ruby") 