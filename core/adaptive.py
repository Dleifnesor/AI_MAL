"""Adaptive Nmap Scanner with Metasploit Integration."""

import logging
import os
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
import json
import asyncio

from .scanner import DirectNmapScanner
from .metasploit_manager import MetasploitManager
from .service_analyzer import ServiceAnalyzer

logger = logging.getLogger(__name__)

@dataclass
class ScanConfig:
    """Configuration for adaptive scanning."""
    target: str
    ports: str = "1-1000"
    scan_type: str = "basic"
    stealth: bool = False
    continuous: bool = False
    delay: int = 300
    output_dir: str = "scan_results"
    vuln_db_path: Optional[str] = None
    workspace: str = "ai_mal_workspace"
    auto_discover: bool = False
    network: Optional[str] = None
    interface: Optional[str] = None
    scan_all: bool = False
    services: bool = False
    version_detection: bool = False
    os_detection: bool = False
    vulnerability_scan: bool = False
    custom_vuln_file: Optional[str] = None
    output_format: str = "xml"
    quiet: bool = False
    iterations: int = 1
    generate_script: bool = False

class AdaptiveNmapScanner:
    """Advanced Adaptive Nmap Scanner with Metasploit Integration."""
    
    def __init__(self, config: ScanConfig):
        """Initialize the scanner.
        
        Args:
            config: Scan configuration
        """
        self.config = config
        self.scanner = DirectNmapScanner()
        self.metasploit = MetasploitManager(config.workspace)
        self.service_analyzer = ServiceAnalyzer()
        
        # Create output directory if it doesn't exist
        os.makedirs(config.output_dir, exist_ok=True)
    
    async def run(self) -> Dict[str, Any]:
        """Execute the full scanning workflow.
        
        Returns:
            Dict containing scan results and vulnerability information
        """
        logger.info("Starting Adaptive Nmap Scanner")
        scan_targets = self._get_scan_targets()
        
        if not scan_targets:
            logger.error("No targets specified")
            return {}
            
        # Run the scans in iterations
        scan_results = []
        vuln_results = []
        
        if self.config.continuous:
            await self._run_continuous_scan(scan_targets, scan_results, vuln_results)
        else:
            await self._run_fixed_scan(scan_targets, scan_results, vuln_results)
            
        # Save final results
        if self.config.output_file:
            self._save_results(scan_results, vuln_results)
            
        # Generate attack script if requested
        if self.config.generate_script:
            script_path = self._generate_attack_script(scan_results, vuln_results)
            if script_path:
                logger.info(f"Attack script generated: {script_path}")
                
        logger.info("Adaptive Nmap Scanner completed successfully")
        
        return {
            "scan_results": scan_results,
            "vulnerability_results": vuln_results,
            "targets": scan_targets
        }
    
    def _get_scan_targets(self) -> List[str]:
        """Get list of targets to scan.
        
        Returns:
            List of target IP addresses or ranges
        """
        targets = []
        
        if self.config.auto_discover and self.config.network:
            # Use network discovery to find targets
            discovery = NetworkDiscovery(self.config.network)
            targets = discovery.discover_hosts()
        else:
            # Use provided target
            targets = [self.config.target]
            
        if not self.config.scan_all:
            # Limit number of targets
            targets = self._select_targets(targets)
            
        return targets
    
    async def _run_continuous_scan(self, targets: List[str], scan_results: List[Dict], vuln_results: List[Dict]):
        """Run continuous scanning with specified delay.
        
        Args:
            targets: List of targets to scan
            scan_results: List to store scan results
            vuln_results: List to store vulnerability results
        """
        iteration = 0
        while True:
            logger.info(f"Starting scan iteration {iteration + 1}")
            results = await self._execute_nmap_scan(targets)
            if results:
                scan_results.append(results)
                
                if self.config.vulnerability_scan:
                    vuln_scan = await self._run_vulnerability_scan(results)
                    if vuln_scan:
                        vuln_results.append(vuln_scan)
                        
            iteration += 1
            if iteration >= self.config.iterations:
                break
                
            logger.info(f"Waiting {self.config.delay} seconds before next scan...")
            await asyncio.sleep(self.config.delay)
    
    async def _run_fixed_scan(self, targets: List[str], scan_results: List[Dict], vuln_results: List[Dict]):
        """Run fixed number of scan iterations.
        
        Args:
            targets: List of targets to scan
            scan_results: List to store scan results
            vuln_results: List to store vulnerability results
        """
        for iteration in range(self.config.iterations):
            logger.info(f"Starting scan iteration {iteration + 1}")
            results = await self._execute_nmap_scan(targets)
            if results:
                scan_results.append(results)
                
                if self.config.vulnerability_scan:
                    vuln_scan = await self._run_vulnerability_scan(results)
                    if vuln_scan:
                        vuln_results.append(vuln_scan)
                        
            if iteration < self.config.iterations - 1:
                logger.info(f"Waiting {self.config.delay} seconds before next scan...")
                await asyncio.sleep(self.config.delay)
    
    async def _execute_nmap_scan(self, targets: List[str]) -> Optional[Dict]:
        """Execute Nmap scan on targets.
        
        Args:
            targets: List of targets to scan
            
        Returns:
            Scan results dictionary or None if scan failed
        """
        try:
            # Build Nmap command
            cmd = ["nmap"]
            
            if self.config.stealth:
                cmd.append("-sS")
            else:
                cmd.append("-sV")
                
            if self.config.services:
                cmd.append("-sV")
            if self.config.version_detection:
                cmd.append("-sV")
            if self.config.os_detection:
                cmd.append("-O")
                
            cmd.extend(["-p", self.config.ports])
            if self.config.interface:
                cmd.extend(["-e", self.config.interface])
                
            cmd.extend(["-oX", "-"])
            cmd.extend(targets)
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Nmap scan failed: {stderr.decode()}")
                return None
                
            # Parse results
            tree = ET.fromstring(stdout.decode())
            return self._parse_nmap_xml(tree)
            
        except Exception as e:
            logger.error(f"Error executing Nmap scan: {e}")
            return None
    
    async def _run_vulnerability_scan(self, scan_results: Dict) -> Optional[Dict]:
        """Run vulnerability scan on scan results.
        
        Args:
            scan_results: Results from Nmap scan
            
        Returns:
            Vulnerability scan results or None if scan failed
        """
        try:
            vuln_results = {}
            
            for host in scan_results.get("hosts", []):
                host_ip = host.get("ip")
                if not host_ip:
                    continue
                    
                # Run Metasploit modules
                if self.config.vuln_db_path:
                    vuln_results[host_ip] = await self.metasploit.run_vuln_scan(
                        host_ip,
                        self.config.vuln_db_path
                    )
                    
            return vuln_results
            
        except Exception as e:
            logger.error(f"Error running vulnerability scan: {e}")
            return None
    
    def _parse_nmap_xml(self, tree: ET.Element) -> Dict:
        """Parse Nmap XML output.
        
        Args:
            tree: XML element tree
            
        Returns:
            Parsed scan results
        """
        results = {
            "hosts": [],
            "scan_info": {}
        }
        
        # Parse scan info
        scan_info = tree.find("scaninfo")
        if scan_info is not None:
            results["scan_info"] = {
                "type": scan_info.get("type"),
                "protocol": scan_info.get("protocol"),
                "numservices": scan_info.get("numservices"),
                "services": scan_info.get("services")
            }
            
        # Parse hosts
        for host in tree.findall("host"):
            host_data = self._parse_host(host)
            if host_data:
                results["hosts"].append(host_data)
                
        return results
    
    def _parse_host(self, host_elem: ET.Element) -> Optional[Dict]:
        """Parse host element from Nmap XML.
        
        Args:
            host_elem: Host XML element
            
        Returns:
            Parsed host data or None if parsing failed
        """
        try:
            host_data = {}
            
            # Get IP address
            address = host_elem.find("address")
            if address is not None:
                host_data["ip"] = address.get("addr")
                host_data["type"] = address.get("addrtype")
                
            # Get hostname
            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                host_data["hostnames"] = []
                for hostname in hostnames.findall("hostname"):
                    host_data["hostnames"].append({
                        "name": hostname.get("name"),
                        "type": hostname.get("type")
                    })
                    
            # Get ports
            ports = host_elem.find("ports")
            if ports is not None:
                host_data["ports"] = []
                for port in ports.findall("port"):
                    port_data = {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": port.get("state"),
                        "service": port.get("name")
                    }
                    
                    # Get service details
                    service = port.find("service")
                    if service is not None:
                        port_data.update({
                            "product": service.get("product"),
                            "version": service.get("version"),
                            "extrainfo": service.get("extrainfo"),
                            "ostype": service.get("ostype")
                        })
                        
                    host_data["ports"].append(port_data)
                    
            # Get OS information
            os_elem = host_elem.find("os")
            if os_elem is not None:
                host_data["os"] = []
                for os_match in os_elem.findall("osmatch"):
                    host_data["os"].append({
                        "name": os_match.get("name"),
                        "accuracy": os_match.get("accuracy")
                    })
                    
            return host_data
            
        except Exception as e:
            logger.error(f"Error parsing host data: {e}")
            return None
    
    def _select_targets(self, hosts: List[str], limit: int = 10) -> List[str]:
        """Select targets to scan, limiting the number if necessary.
        
        Args:
            hosts: List of available hosts
            limit: Maximum number of targets to select
            
        Returns:
            Selected targets
        """
        if len(hosts) <= limit:
            return hosts
        return hosts[:limit]
    
    def _save_results(self, scan_results: List[Dict], vuln_results: List[Dict]):
        """Save scan and vulnerability results.
        
        Args:
            scan_results: List of scan results
            vuln_results: List of vulnerability results
        """
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        # Save scan results
        scan_file = os.path.join(self.config.output_dir, f"scan_results_{timestamp}.{self.config.output_format}")
        with open(scan_file, "w") as f:
            if self.config.output_format == "json":
                json.dump(scan_results, f, indent=2)
            else:
                # Convert to XML format
                root = ET.Element("scan_results")
                for result in scan_results:
                    result_elem = ET.SubElement(root, "result")
                    for key, value in result.items():
                        if isinstance(value, (list, dict)):
                            value = json.dumps(value)
                        ET.SubElement(result_elem, key).text = str(value)
                tree = ET.ElementTree(root)
                tree.write(scan_file, encoding="utf-8", xml_declaration=True)
                
        # Save vulnerability results
        if vuln_results:
            vuln_file = os.path.join(self.config.output_dir, f"vuln_results_{timestamp}.json")
            with open(vuln_file, "w") as f:
                json.dump(vuln_results, f, indent=2)
                
        logger.info(f"Results saved to {self.config.output_dir}")
    
    def _generate_attack_script(self, scan_results: List[Dict], vuln_results: List[Dict]) -> Optional[str]:
        """Generate attack script based on scan results.
        
        Args:
            scan_results: List of scan results
            vuln_results: List of vulnerability results
            
        Returns:
            Path to generated script or None if generation failed
        """
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            script_path = os.path.join(self.config.output_dir, f"attack_script_{timestamp}.py")
            
            with open(script_path, "w") as f:
                f.write("""#!/usr/bin/env python3
# Generated attack script for penetration testing
# WARNING: This script is for educational purposes only
# Always obtain proper authorization before using

import logging
import sys
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    # TODO: Implement attack logic based on scan results
    logger.info("Attack script generated successfully")
    logger.info("Please implement the attack logic based on your requirements")

if __name__ == "__main__":
    main()
""")
                
            return script_path
            
        except Exception as e:
            logger.error(f"Error generating attack script: {e}")
            return None 