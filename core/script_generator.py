import asyncio
import json
import logging
import os
from typing import Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)

class ScriptGenerator:
    def __init__(self):
        self.script_dir = Path("generated_scripts")
        self.script_dir.mkdir(exist_ok=True)
    
    async def generate_scripts(self, scan_results: Dict[str, Any], script_type: str = 'python') -> Dict[str, str]:
        """Generate custom exploitation scripts based on scan results."""
        try:
            scripts = {}
            
            # Generate different types of scripts
            if script_type == 'python':
                scripts.update(await self._generate_python_scripts(scan_results))
            elif script_type == 'bash':
                scripts.update(await self._generate_bash_scripts(scan_results))
            elif script_type == 'ruby':
                scripts.update(await self._generate_ruby_scripts(scan_results))
            
            return scripts
            
        except Exception as e:
            logger.error(f"Error generating scripts: {str(e)}")
            return {}
    
    async def execute_scripts(self, scripts: Dict[str, str]) -> None:
        """Execute generated scripts."""
        try:
            for filename, content in scripts.items():
                script_path = self.script_dir / filename
                
                # Save script
                with open(script_path, 'w') as f:
                    f.write(content)
                
                # Make script executable
                os.chmod(script_path, 0o755)
                
                # Execute script
                await self._run_script(script_path)
                
        except Exception as e:
            logger.error(f"Error executing scripts: {str(e)}")
    
    async def _generate_python_scripts(self, scan_results: Dict[str, Any]) -> Dict[str, str]:
        """Generate Python exploitation scripts."""
        scripts = {}
        
        # Generate port scanner
        scripts['port_scanner.py'] = self._create_python_port_scanner(scan_results)
        
        # Generate service enumerator
        scripts['service_enumerator.py'] = self._create_python_service_enumerator(scan_results)
        
        # Generate vulnerability scanner
        scripts['vuln_scanner.py'] = self._create_python_vuln_scanner(scan_results)
        
        return scripts
    
    async def _generate_bash_scripts(self, scan_results: Dict[str, Any]) -> Dict[str, str]:
        """Generate Bash exploitation scripts."""
        scripts = {}
        
        # Generate port scanner
        scripts['port_scanner.sh'] = self._create_bash_port_scanner(scan_results)
        
        # Generate service enumerator
        scripts['service_enumerator.sh'] = self._create_bash_service_enumerator(scan_results)
        
        # Generate vulnerability scanner
        scripts['vuln_scanner.sh'] = self._create_bash_vuln_scanner(scan_results)
        
        return scripts
    
    async def _generate_ruby_scripts(self, scan_results: Dict[str, Any]) -> Dict[str, str]:
        """Generate Ruby exploitation scripts."""
        scripts = {}
        
        # Generate port scanner
        scripts['port_scanner.rb'] = self._create_ruby_port_scanner(scan_results)
        
        # Generate service enumerator
        scripts['service_enumerator.rb'] = self._create_ruby_service_enumerator(scan_results)
        
        # Generate vulnerability scanner
        scripts['vuln_scanner.rb'] = self._create_ruby_vuln_scanner(scan_results)
        
        return scripts
    
    def _create_python_port_scanner(self, scan_results: Dict[str, Any]) -> str:
        """Create Python port scanner script."""
        return f"""#!/usr/bin/env python3
import socket
import sys
import logging
from typing import List, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def scan_ports(target: str, ports: List[int]) -> Dict[int, str]:
    results = {{}}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = socket.getservbyport(port)
                results[port] = service
            sock.close()
        except Exception as e:
            logger.error(f"Error scanning port {port}: {e}")
    return results

if __name__ == "__main__":
    target = "{scan_results.get('hosts', [{}])[0].get('addresses', [{}])[0].get('addr', '')}"
    ports = [port.get('portid') for port in scan_results.get('hosts', [{}])[0].get('ports', [])]
    
    results = scan_ports(target, ports)
    for port, service in results.items():
        print(f"Port {port}: {service}")
"""
    
    def _create_python_service_enumerator(self, scan_results: Dict[str, Any]) -> str:
        """Create Python service enumerator script."""
        return f"""#!/usr/bin/env python3
import socket
import sys
import logging
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def enumerate_service(host: str, port: int) -> Dict[str, Any]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        # Send service-specific probes
        probes = [
            b"HEAD / HTTP/1.0\\r\\n\\r\\n",
            b"GET / HTTP/1.0\\r\\n\\r\\n",
            b"OPTIONS / HTTP/1.0\\r\\n\\r\\n"
        ]
        
        results = {{}}
        for probe in probes:
            try:
                sock.send(probe)
                response = sock.recv(1024)
                results[probe.decode()] = response.decode()
            except Exception as e:
                logger.error(f"Error with probe {probe}: {e}")
        
        sock.close()
        return results
        
    except Exception as e:
        logger.error(f"Error enumerating service: {e}")
        return {{}}

if __name__ == "__main__":
    target = "{scan_results.get('hosts', [{}])[0].get('addresses', [{}])[0].get('addr', '')}"
    ports = [port.get('portid') for port in scan_results.get('hosts', [{}])[0].get('ports', [])]
    
    for port in ports:
        print(f"\\nEnumerating service on port {port}:")
        results = enumerate_service(target, port)
        for probe, response in results.items():
            print(f"\\nProbe: {probe}")
            print(f"Response: {response}")
"""
    
    def _create_python_vuln_scanner(self, scan_results: Dict[str, Any]) -> str:
        """Create Python vulnerability scanner script."""
        return f"""#!/usr/bin/env python3
import socket
import sys
import logging
from typing import List, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_vulnerabilities(host: str, port: int, service: str) -> List[Dict[str, str]]:
    vulnerabilities = []
    
    # Common vulnerability checks
    if service.lower() == 'http':
        # Check for common web vulnerabilities
        vulns = check_web_vulnerabilities(host, port)
        vulnerabilities.extend(vulns)
    elif service.lower() == 'ftp':
        # Check for FTP vulnerabilities
        vulns = check_ftp_vulnerabilities(host, port)
        vulnerabilities.extend(vulns)
    elif service.lower() == 'ssh':
        # Check for SSH vulnerabilities
        vulns = check_ssh_vulnerabilities(host, port)
        vulnerabilities.extend(vulns)
    
    return vulnerabilities

def check_web_vulnerabilities(host: str, port: int) -> List[Dict[str, str]]:
    vulns = []
    try:
        # Check for XSS
        xss_payload = "<script>alert('XSS')</script>"
        # ... implement XSS check
        
        # Check for SQL Injection
        sql_payload = "' OR '1'='1"
        # ... implement SQL injection check
        
        # Check for Directory Traversal
        traversal_payload = "../../../etc/passwd"
        # ... implement directory traversal check
        
    except Exception as e:
        logger.error(f"Error checking web vulnerabilities: {e}")
    return vulns

def check_ftp_vulnerabilities(host: str, port: int) -> List[Dict[str, str]]:
    vulns = []
    try:
        # Check for anonymous login
        # ... implement anonymous login check
        
        # Check for weak credentials
        # ... implement weak credentials check
        
    except Exception as e:
        logger.error(f"Error checking FTP vulnerabilities: {e}")
    return vulns

def check_ssh_vulnerabilities(host: str, port: int) -> List[Dict[str, str]]:
    vulns = []
    try:
        # Check for weak algorithms
        # ... implement weak algorithms check
        
        # Check for known vulnerabilities
        # ... implement known vulnerabilities check
        
    except Exception as e:
        logger.error(f"Error checking SSH vulnerabilities: {e}")
    return vulns

if __name__ == "__main__":
    target = "{scan_results.get('hosts', [{}])[0].get('addresses', [{}])[0].get('addr', '')}"
    ports = [port.get('portid') for port in scan_results.get('hosts', [{}])[0].get('ports', [])]
    
    for port in ports:
        service = scan_results.get('hosts', [{}])[0].get('ports', [{}])[0].get('service', {}).get('name', '')
        print(f"\\nChecking vulnerabilities for {service} on port {port}:")
        vulns = check_vulnerabilities(target, port, service)
        for vuln in vulns:
            print(f"\\nVulnerability: {vuln.get('name')}")
            print(f"Description: {vuln.get('description')}")
            print(f"Severity: {vuln.get('severity')}")
"""
    
    def _create_bash_port_scanner(self, scan_results: Dict[str, Any]) -> str:
        """Create Bash port scanner script."""
        return f"""#!/bin/bash

target="{scan_results.get('hosts', [{}])[0].get('addresses', [{}])[0].get('addr', '')}"
ports=({[port.get('portid') for port in scan_results.get('hosts', [{}])[0].get('ports', [])]})

for port in "${{ports[@]}}"; do
    (echo >/dev/tcp/$target/$port) &>/dev/null
    if [ $? -eq 0 ]; then
        service=$(getent services $port | cut -d' ' -f1)
        echo "Port $port: $service"
    fi
done
"""
    
    def _create_bash_service_enumerator(self, scan_results: Dict[str, Any]) -> str:
        """Create Bash service enumerator script."""
        return f"""#!/bin/bash

target="{scan_results.get('hosts', [{}])[0].get('addresses', [{}])[0].get('addr', '')}"
ports=({[port.get('portid') for port in scan_results.get('hosts', [{}])[0].get('ports', [])]})

for port in "${{ports[@]}}"; do
    echo "Enumerating service on port $port:"
    
    # HTTP enumeration
    if [ $port -eq 80 ] || [ $port -eq 443 ]; then
        echo "Testing HTTP/HTTPS..."
        curl -I http://$target:$port
        curl -I https://$target:$port
    fi
    
    # FTP enumeration
    if [ $port -eq 21 ]; then
        echo "Testing FTP..."
        ftp -n $target $port << EOF
user anonymous anonymous
ls
quit
EOF
    fi
    
    # SSH enumeration
    if [ $port -eq 22 ]; then
        echo "Testing SSH..."
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 $target -p $port "echo 'SSH connection successful'"
    fi
done
"""
    
    def _create_bash_vuln_scanner(self, scan_results: Dict[str, Any]) -> str:
        """Create Bash vulnerability scanner script."""
        return f"""#!/bin/bash

target="{scan_results.get('hosts', [{}])[0].get('addresses', [{}])[0].get('addr', '')}"
ports=({[port.get('portid') for port in scan_results.get('hosts', [{}])[0].get('ports', [])]})

for port in "${{ports[@]}}"; do
    echo "Checking vulnerabilities for port $port:"
    
    # Web vulnerabilities
    if [ $port -eq 80 ] || [ $port -eq 443 ]; then
        echo "Checking web vulnerabilities..."
        
        # XSS check
        curl -X POST "http://$target:$port/search" -d "q=<script>alert('XSS')</script>"
        
        # SQL Injection check
        curl -X POST "http://$target:$port/login" -d "username=' OR '1'='1"
        
        # Directory Traversal check
        curl "http://$target:$port/../../../etc/passwd"
    fi
    
    # FTP vulnerabilities
    if [ $port -eq 21 ]; then
        echo "Checking FTP vulnerabilities..."
        
        # Anonymous login check
        ftp -n $target $port << EOF
user anonymous anonymous
ls
quit
EOF
    fi
    
    # SSH vulnerabilities
    if [ $port -eq 22 ]; then
        echo "Checking SSH vulnerabilities..."
        
        # Weak algorithms check
        ssh -o KexAlgorithms=diffie-hellman-group1-sha1 $target -p $port
    fi
done
"""
    
    def _create_ruby_port_scanner(self, scan_results: Dict[str, Any]) -> str:
        """Create Ruby port scanner script."""
        return f"""#!/usr/bin/env ruby

require 'socket'
require 'timeout'

target = "{scan_results.get('hosts', [{}])[0].get('addresses', [{}])[0].get('addr', '')}"
ports = {[port.get('portid') for port in scan_results.get('hosts', [{}])[0].get('ports', [])]}

ports.each do |port|
  begin
    Timeout.timeout(1) do
      socket = TCPSocket.new(target, port)
      service = Socket.getservbyport(port)
      puts "Port #{port}: #{service}"
      socket.close
    end
  rescue Timeout::Error
    next
  rescue => e
    puts "Error scanning port #{port}: #{e.message}"
  end
end
"""
    
    def _create_ruby_service_enumerator(self, scan_results: Dict[str, Any]) -> str:
        """Create Ruby service enumerator script."""
        return f"""#!/usr/bin/env ruby

require 'socket'
require 'net/http'
require 'net/ftp'
require 'net/ssh'

target = "{scan_results.get('hosts', [{}])[0].get('addresses', [{}])[0].get('addr', '')}"
ports = {[port.get('portid') for port in scan_results.get('hosts', [{}])[0].get('ports', [])]}

ports.each do |port|
  puts "\\nEnumerating service on port #{port}:"
  
  begin
    case port
    when 80, 443
      puts "Testing HTTP/HTTPS..."
      uri = URI("http://#{target}:#{port}")
      response = Net::HTTP.get_response(uri)
      puts "Response: #{response.code} #{response.message}"
      
    when 21
      puts "Testing FTP..."
      ftp = Net::FTP.new
      ftp.connect(target, port)
      ftp.login('anonymous', 'anonymous')
      puts "FTP Directory Listing:"
      ftp.list.each { |file| puts file }
      ftp.quit
      
    when 22
      puts "Testing SSH..."
      Net::SSH.start(target, 'root', port: port, timeout: 5) do |ssh|
        result = ssh.exec!("echo 'SSH connection successful'")
        puts result
      end
    end
  rescue => e
    puts "Error enumerating port #{port}: #{e.message}"
  end
end
"""
    
    def _create_ruby_vuln_scanner(self, scan_results: Dict[str, Any]) -> str:
        """Create Ruby vulnerability scanner script."""
        return f"""#!/usr/bin/env ruby

require 'socket'
require 'net/http'
require 'net/ftp'
require 'net/ssh'

target = "{scan_results.get('hosts', [{}])[0].get('addresses', [{}])[0].get('addr', '')}"
ports = {[port.get('portid') for port in scan_results.get('hosts', [{}])[0].get('ports', [])]}

def check_web_vulnerabilities(target, port)
  puts "Checking web vulnerabilities..."
  
  # XSS check
  uri = URI("http://#{target}:#{port}/search")
  http = Net::HTTP.new(uri.host, uri.port)
  request = Net::HTTP::Post.new(uri.path)
  request.set_form_data('q' => "<script>alert('XSS')</script>")
  response = http.request(request)
  puts "XSS Test Response: #{response.code}"
  
  # SQL Injection check
  uri = URI("http://#{target}:#{port}/login")
  request = Net::HTTP::Post.new(uri.path)
  request.set_form_data('username' => "' OR '1'='1")
  response = http.request(request)
  puts "SQL Injection Test Response: #{response.code}"
  
  # Directory Traversal check
  uri = URI("http://#{target}:#{port}/../../../etc/passwd")
  response = Net::HTTP.get_response(uri)
  puts "Directory Traversal Test Response: #{response.code}"
end

def check_ftp_vulnerabilities(target, port)
  puts "Checking FTP vulnerabilities..."
  
  begin
    ftp = Net::FTP.new
    ftp.connect(target, port)
    ftp.login('anonymous', 'anonymous')
    puts "Anonymous FTP login successful!"
    ftp.quit
  rescue => e
    puts "FTP vulnerability check failed: #{e.message}"
  end
end

def check_ssh_vulnerabilities(target, port)
  puts "Checking SSH vulnerabilities..."
  
  begin
    Net::SSH.start(target, 'root', port: port, timeout: 5) do |ssh|
      result = ssh.exec!("echo 'SSH connection successful'")
      puts "SSH connection successful: #{result}"
    end
  rescue => e
    puts "SSH vulnerability check failed: #{e.message}"
  end
end

ports.each do |port|
  puts "\\nChecking vulnerabilities for port #{port}:"
  
  case port
  when 80, 443
    check_web_vulnerabilities(target, port)
  when 21
    check_ftp_vulnerabilities(target, port)
  when 22
    check_ssh_vulnerabilities(target, port)
  end
end
"""
    
    async def _run_script(self, script_path: Path) -> None:
        """Run a generated script."""
        try:
            # Determine script type and command
            if script_path.suffix == '.py':
                cmd = ['python3', str(script_path)]
            elif script_path.suffix == '.sh':
                cmd = ['bash', str(script_path)]
            elif script_path.suffix == '.rb':
                cmd = ['ruby', str(script_path)]
            else:
                raise ValueError(f"Unsupported script type: {script_path.suffix}")
            
            # Run script
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Script execution failed: {stderr.decode()}")
                return
            
            logger.info(f"Script output: {stdout.decode()}")
            
        except Exception as e:
            logger.error(f"Error running script: {str(e)}") 