#!/usr/bin/env python3
"""
Adaptive scanning module for AI_MAL
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

class AdaptiveScanner:
    def __init__(self, target: str):
        self.target = target
        self.scan_results_dir = os.getenv('SCAN_RESULTS_DIR', 'scan_results')
        os.makedirs(self.scan_results_dir, exist_ok=True)

    async def scan(
        self,
        stealth: bool = False,
        continuous: bool = False,
        delay: int = 300,
        services: bool = False,
        version: bool = False,
        os_detection: bool = False,
        vuln_scan: bool = False,
        dos: bool = False
    ) -> Dict[str, Any]:
        """
        Perform an adaptive scan based on the provided parameters
        """
        try:
            # Build nmap command based on parameters
            nmap_args = ['nmap']
            
            if stealth:
                nmap_args.extend(['-sS', '-T2', '--randomize-hosts'])
            else:
                nmap_args.extend(['-sV', '-sC'])
            
            if services:
                nmap_args.append('-sV')
            if version:
                nmap_args.append('--version-intensity 5')
            if os_detection:
                nmap_args.append('-O')
            if vuln_scan:
                nmap_args.append('--script vuln')
            if dos:
                nmap_args.append('--max-retries 1')
            
            nmap_args.append(self.target)
            
            # Run nmap scan
            logger.info(f"Starting scan with command: {' '.join(nmap_args)}")
            process = await asyncio.create_subprocess_exec(
                *nmap_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Scan failed: {stderr.decode()}")
                raise Exception(f"Nmap scan failed: {stderr.decode()}")
            
            # Parse scan results
            results = self._parse_nmap_output(stdout.decode())
            
            # Save results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(self.scan_results_dir, f'scan_results_{timestamp}.json')
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Scan results saved to {output_file}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            raise

    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """
        Parse nmap output into structured data
        """
        results = {
            "scan_info": {
                "scan_start": datetime.now().isoformat(),
                "scan_end": datetime.now().isoformat(),
                "scan_type": "stealth" if "-sS" in output else "normal",
                "target": self.target
            },
            "hosts": []
        }
        
        # Extract scan time information
        start_match = re.search(r'Nmap scan report for (.+)', output)
        if start_match:
            results["scan_info"]["start_time"] = datetime.now().isoformat()
        
        # Parse host information
        current_host = None
        lines = output.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # New host found
            if line.startswith('Nmap scan report for'):
                if current_host:
                    results["hosts"].append(current_host)
                
                # Extract IP and hostname
                ip_match = re.search(r'Nmap scan report for ([\w\.-]+) \(([\d\.]+)\)', line)
                if ip_match:
                    hostname, ip = ip_match.groups()
                    current_host = {
                        "ip": ip,
                        "hostname": hostname,
                        "status": "unknown",
                        "ports": [],
                        "os": {}
                    }
                else:
                    ip_match = re.search(r'Nmap scan report for ([\d\.]+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        current_host = {
                            "ip": ip,
                            "hostname": None,
                            "status": "unknown",
                            "ports": [],
                            "os": {}
                        }
                
            # Host status
            elif line.startswith('Host is ') and current_host:
                current_host["status"] = "up" if "up" in line else "down"
            
            # Port information
            elif '/tcp' in line or '/udp' in line and current_host:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split('/')
                    port = int(port_proto[0])
                    protocol = port_proto[1]
                    state = parts[1]
                    service = parts[2]
                    
                    # Get version info if available
                    version = ""
                    if len(parts) > 3:
                        version = ' '.join(parts[3:])
                    
                    current_host["ports"].append({
                        "port": port,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "version": version
                    })
            
            # OS detection
            elif line.startswith('OS details:') and current_host:
                os_info = line.replace('OS details:', '').strip()
                os_parts = os_info.split(',')
                
                current_host["os"] = {
                    "name": os_parts[0].strip(),
                    "family": os_parts[1].strip() if len(os_parts) > 1 else "",
                    "accuracy": 100  # Default accuracy
                }
                
                # Look for accuracy info
                for j in range(i+1, min(i+5, len(lines))):
                    if "OS CPE:" in lines[j]:
                        current_host["os"]["cpe"] = lines[j].split("OS CPE:")[1].strip()
                    if "Aggressive OS guesses:" in lines[j]:
                        current_host["os"]["guesses"] = lines[j].split("Aggressive OS guesses:")[1].strip()
                    if "OS accuracy:" in lines[j]:
                        accuracy_match = re.search(r'OS accuracy: (\d+)', lines[j])
                        if accuracy_match:
                            current_host["os"]["accuracy"] = int(accuracy_match.group(1))
            
            i += 1
        
        # Add the last host if there is one
        if current_host:
            results["hosts"].append(current_host)
        
        # If no hosts were found, add the target as a down host
        if not results["hosts"]:
            results["hosts"].append({
                "ip": self.target,
                "hostname": None,
                "status": "down",
                "ports": [],
                "os": {}
            })
        
        return results 