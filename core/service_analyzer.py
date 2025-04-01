"""Service analyzer for identifying potential vulnerabilities."""

import logging
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import json
import os

logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Information about a potential vulnerability."""
    name: str
    description: str
    severity: str
    cve: Optional[str] = None
    references: List[str] = None
    affected_versions: List[str] = None
    mitigation: Optional[str] = None

@dataclass
class ServiceVulnerability:
    """Vulnerability information for a specific service."""
    service_name: str
    port: int
    protocol: str
    vulnerabilities: List[Vulnerability]
    version: Optional[str] = None
    product: Optional[str] = None

class ServiceAnalyzer:
    """Analyzes services for potential vulnerabilities."""
    
    def __init__(self, vuln_db_path: Optional[str] = None):
        """Initialize the service analyzer.
        
        Args:
            vuln_db_path: Path to custom vulnerability database
        """
        self.vuln_db_path = vuln_db_path
        self.vuln_db = self._load_vuln_db()
        
    def _load_vuln_db(self) -> Dict:
        """Load vulnerability database.
        
        Returns:
            Dictionary containing vulnerability information
        """
        if self.vuln_db_path and os.path.exists(self.vuln_db_path):
            try:
                with open(self.vuln_db_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading custom vulnerability database: {e}")
                
        # Default vulnerability database
        return {
            "common_vulnerabilities": {
                "ftp": [
                    {
                        "name": "Anonymous FTP Access",
                        "description": "FTP server allows anonymous access",
                        "severity": "high",
                        "mitigation": "Disable anonymous access"
                    }
                ],
                "ssh": [
                    {
                        "name": "Weak SSH Configuration",
                        "description": "SSH server with weak configuration",
                        "severity": "medium",
                        "mitigation": "Implement strong SSH configuration"
                    }
                ],
                "http": [
                    {
                        "name": "Directory Traversal",
                        "description": "Potential directory traversal vulnerability",
                        "severity": "high",
                        "mitigation": "Implement proper path validation"
                    }
                ]
            }
        }
        
    def analyze_service(self, service_name: str, port: int, protocol: str,
                       version: Optional[str] = None, product: Optional[str] = None) -> ServiceVulnerability:
        """Analyze a service for potential vulnerabilities.
        
        Args:
            service_name: Name of the service
            port: Port number
            protocol: Protocol (tcp/udp)
            version: Service version
            product: Product name
            
        Returns:
            ServiceVulnerability object containing vulnerability information
        """
        vulnerabilities = []
        
        # Check common vulnerabilities
        if service_name.lower() in self.vuln_db["common_vulnerabilities"]:
            for vuln in self.vuln_db["common_vulnerabilities"][service_name.lower()]:
                vulnerabilities.append(Vulnerability(
                    name=vuln["name"],
                    description=vuln["description"],
                    severity=vuln["severity"],
                    mitigation=vuln.get("mitigation")
                ))
                
        # Check version-specific vulnerabilities
        if version and product:
            version_vulns = self._check_version_vulnerabilities(service_name, version, product)
            vulnerabilities.extend(version_vulns)
            
        # Check protocol-specific vulnerabilities
        protocol_vulns = self._check_protocol_vulnerabilities(protocol, port)
        vulnerabilities.extend(protocol_vulns)
        
        return ServiceVulnerability(
            service_name=service_name,
            port=port,
            protocol=protocol,
            vulnerabilities=vulnerabilities,
            version=version,
            product=product
        )
        
    def _check_version_vulnerabilities(self, service_name: str, version: str, product: str) -> List[Vulnerability]:
        """Check for version-specific vulnerabilities.
        
        Args:
            service_name: Name of the service
            version: Service version
            product: Product name
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        # Version-specific checks
        if service_name.lower() == "apache" and version.startswith("2.4"):
            vulnerabilities.append(Vulnerability(
                name="Apache 2.4.x Vulnerability",
                description="Known vulnerability in Apache 2.4.x",
                severity="high",
                cve="CVE-2021-41773",
                mitigation="Upgrade to latest version"
            ))
            
        return vulnerabilities
        
    def _check_protocol_vulnerabilities(self, protocol: str, port: int) -> List[Vulnerability]:
        """Check for protocol-specific vulnerabilities.
        
        Args:
            protocol: Protocol (tcp/udp)
            port: Port number
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        # Protocol-specific checks
        if protocol.lower() == "tcp":
            if port == 21:
                vulnerabilities.append(Vulnerability(
                    name="FTP Plaintext",
                    description="FTP transmits data in plaintext",
                    severity="medium",
                    mitigation="Use SFTP or FTPS"
                ))
            elif port == 23:
                vulnerabilities.append(Vulnerability(
                    name="Telnet Plaintext",
                    description="Telnet transmits data in plaintext",
                    severity="high",
                    mitigation="Use SSH instead"
                ))
                
        return vulnerabilities
        
    def generate_report(self, service_vulns: List[ServiceVulnerability], output_file: str):
        """Generate a vulnerability report.
        
        Args:
            service_vulns: List of service vulnerabilities
            output_file: Path to save the report
        """
        try:
            report = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "services": []
            }
            
            for sv in service_vulns:
                service_info = {
                    "name": sv.service_name,
                    "port": sv.port,
                    "protocol": sv.protocol,
                    "version": sv.version,
                    "product": sv.product,
                    "vulnerabilities": [
                        {
                            "name": v.name,
                            "description": v.description,
                            "severity": v.severity,
                            "cve": v.cve,
                            "mitigation": v.mitigation
                        }
                        for v in sv.vulnerabilities
                    ]
                }
                report["services"].append(service_info)
                
            # Write report to file
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
                
            logger.info(f"Generated vulnerability report: {output_file}")
            
        except Exception as e:
            logger.error(f"Error generating vulnerability report: {e}")
            raise 