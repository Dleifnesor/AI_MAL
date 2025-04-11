#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL Vulnerability Scanner Module
==================================

This module handles vulnerability scanning using OpenVAS or nmap NSE scripts.
"""

import os
import json
import time
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from .logger import LoggerWrapper

class VulnerabilityScanner:
    """
    Vulnerability scanner class that uses OpenVAS for comprehensive vulnerability scanning.
    """
    
    def __init__(self, target, scan_config="full_and_fast", timeout=3600, custom_vuln_file=None, use_nmap=False):
        """
        Initialize the vulnerability scanner.
        
        Args:
            target (str): Target IP, hostname, or network range
            scan_config (str): OpenVAS scan configuration type
            timeout (int): Scan timeout in seconds
            custom_vuln_file (str, optional): Path to custom vulnerability file
            use_nmap (bool): Whether to use nmap instead of OpenVAS (default: False)
        """
        self.target = target
        self.scan_config = scan_config
        self.timeout = timeout
        self.custom_vuln_file = custom_vuln_file
        self.use_nmap = use_nmap
        self.logger = LoggerWrapper("VulnScanner")
        
        # Define OpenVAS scan configurations
        self.openvas_configs = {
            "full_and_fast": "daba56c8-73ec-11df-a475-002264764cea",
            "full_and_fast_ultimate": "698f691e-7489-11df-9d8c-002264764cea",
            "full_and_very_deep": "708f25c4-7489-11df-8094-002264764cea",
            "full_and_very_deep_ultimate": "74db13d6-7489-11df-91b9-002264764cea",
            "system_discovery": "8715c877-47a0-438d-98a3-27c7a6ab2196",
            "system_discovery_ultimate": "bbca7412-a950-11e3-9109-406186ea4fc5"
        }
        
        # Load custom vulnerabilities if file is provided
        if self.custom_vuln_file:
            self.load_custom_vulnerabilities()
    
    def load_custom_vulnerabilities(self):
        """
        Load custom vulnerabilities from file.
        """
        try:
            with open(self.custom_vuln_file, 'r') as f:
                self.custom_vulns = json.load(f)
            self.logger.info(f"Loaded {len(self.custom_vulns)} custom vulnerabilities from {self.custom_vuln_file}")
        except Exception as e:
            self.logger.error(f"Error loading custom vulnerabilities: {str(e)}")
            self.custom_vulns = []
    
    def is_openvas_available(self):
        """
        Check if OpenVAS is available.
        
        Returns:
            bool: True if OpenVAS is available, False otherwise
        """
        try:
            # Check for gvm-cli command
            subprocess.run(["gvm-cli", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            try:
                # Try omp as fallback for older versions
                subprocess.run(["omp", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return True
            except FileNotFoundError:
                return False
    
    def scan_with_openvas(self):
        """
        Perform a vulnerability scan using OpenVAS.
        
        Returns:
            dict: Scan results
        """
        self.logger.info(f"Starting OpenVAS vulnerability scan on {self.target}")
        
        # Get scan config ID
        config_id = self.openvas_configs.get(self.scan_config, self.openvas_configs["full_and_fast"])
        
        try:
            # Check if we're using gvm-cli or omp
            use_gvm = True
            try:
                subprocess.run(["gvm-cli", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except FileNotFoundError:
                use_gvm = False
            
            # Create a target in OpenVAS with proper naming for web interface visibility
            target_name = f"AI_MAL_Target_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.logger.debug(f"Creating target in OpenVAS: {target_name}")
            
            if use_gvm:
                cmd = [
                    "gvm-cli", "socket", "--xml", 
                    f"<create_target><name>{target_name}</name><hosts>{self.target}</hosts><comment>Created by AI_MAL</comment></create_target>"
                ]
            else:
                cmd = ["omp", "-C", "-u", "admin", "-w", "admin", "--xml", 
                       f"<create_target><name>{target_name}</name><hosts>{self.target}</hosts><comment>Created by AI_MAL</comment></create_target>"]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"OpenVAS target creation failed: {stderr.decode()}")
                return {"error": "OpenVAS target creation failed"}
            
            # Parse target ID
            target_xml = ET.fromstring(stdout.decode())
            target_id = target_xml.get("id")
            
            if not target_id:
                self.logger.error("Failed to get target ID from OpenVAS")
                return {"error": "Failed to get target ID from OpenVAS"}
            
            # Create a task in OpenVAS with proper naming and configuration
            task_name = f"AI_MAL_Scan_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.logger.debug(f"Creating scan task in OpenVAS: {task_name}")
            
            if use_gvm:
                cmd = [
                    "gvm-cli", "socket", "--xml", 
                    f"<create_task><name>{task_name}</name><target id=\"{target_id}\"/><config id=\"{config_id}\"/><comment>Created by AI_MAL</comment><preferences><preference><scanner_name>source_iface</scanner_name><value>eth0</value></preference></preferences></create_task>"
                ]
            else:
                cmd = ["omp", "-C", "-u", "admin", "-w", "admin", "--xml", 
                       f"<create_task><name>{task_name}</name><target id=\"{target_id}\"/><config id=\"{config_id}\"/><comment>Created by AI_MAL</comment><preferences><preference><scanner_name>source_iface</scanner_name><value>eth0</value></preference></preferences></create_task>"]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"OpenVAS task creation failed: {stderr.decode()}")
                return {"error": "OpenVAS task creation failed"}
            
            # Parse task ID
            task_xml = ET.fromstring(stdout.decode())
            task_id = task_xml.get("id")
            
            if not task_id:
                self.logger.error("Failed to get task ID from OpenVAS")
                return {"error": "Failed to get task ID from OpenVAS"}
            
            # Start the task
            self.logger.debug("Starting OpenVAS scan task")
            if use_gvm:
                cmd = ["gvm-cli", "socket", "--xml", f"<start_task task_id=\"{task_id}\"/>"]
            else:
                cmd = ["omp", "-C", "-u", "admin", "-w", "admin", "--xml", f"<start_task task_id=\"{task_id}\"/>"]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Failed to start OpenVAS task: {stderr.decode()}")
                return {"error": "Failed to start OpenVAS task"}
            
            # Parse report ID
            report_xml = ET.fromstring(stdout.decode())
            report_id = report_xml.find(".//report_id").text
            
            if not report_id:
                self.logger.error("Failed to get report ID from OpenVAS")
                return {"error": "Failed to get report ID from OpenVAS"}
            
            # Wait for the scan to complete
            self.logger.info(f"OpenVAS scan started. Task ID: {task_id}")
            self.logger.info("You can monitor progress in the Greenbone web interface.")
            self.logger.info("Waiting for scan completion...")
            
            start_time = time.time()
            while True:
                # Check task status
                if use_gvm:
                    cmd = ["gvm-cli", "socket", "--xml", f"<get_tasks task_id=\"{task_id}\"/>"]
                else:
                    cmd = ["omp", "-C", "-u", "admin", "-w", "admin", "--xml", f"<get_tasks task_id=\"{task_id}\"/>"]
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if process.returncode != 0:
                    self.logger.error(f"OpenVAS task status check failed: {stderr.decode()}")
                    return {"error": "OpenVAS task status check failed"}
                
                # Parse task status
                task_xml = ET.fromstring(stdout.decode())
                status = task_xml.find(".//status").text
                
                if status == "Done":
                    break
                
                # Check timeout
                if time.time() - start_time > self.timeout:
                    self.logger.warning("OpenVAS scan timed out. Retrieving partial results.")
                    break
                
                # Wait before checking again
                time.sleep(10)
            
            # Get the report
            self.logger.debug("Retrieving OpenVAS scan results")
            if use_gvm:
                cmd = ["gvm-cli", "socket", "--xml", 
                       f"<get_reports report_id=\"{report_id}\" format_id=\"a994b278-1f62-11e1-96ac-406186ea4fc5\"/>"]
            else:
                cmd = ["omp", "-C", "-u", "admin", "-w", "admin", "--xml", 
                       f"<get_reports report_id=\"{report_id}\" format_id=\"a994b278-1f62-11e1-96ac-406186ea4fc5\"/>"]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"OpenVAS report retrieval failed: {stderr.decode()}")
                return {"error": "OpenVAS report retrieval failed"}
            
            # Parse the XML report
            self.logger.debug("Parsing OpenVAS report XML")
            report_xml = ET.fromstring(stdout.decode())
            
            # Extract vulnerabilities
            results = {
                "scan_info": {
                    "scanner": "OpenVAS",
                    "scan_start": report_xml.find(".//creation_time").text if report_xml.find(".//creation_time") is not None else "",
                    "scan_end": report_xml.find(".//modification_time").text if report_xml.find(".//modification_time") is not None else "",
                    "target": self.target,
                    "scan_config": self.scan_config,
                    "task_id": task_id,
                    "task_name": task_name,
                    "target_id": target_id,
                    "target_name": target_name
                },
                "vulnerabilities": []
            }
            
            for result in report_xml.findall(".//result"):
                vuln = {
                    "name": result.find(".//name").text if result.find(".//name") is not None else "",
                    "host": result.find(".//host").text if result.find(".//host") is not None else "",
                    "port": result.find(".//port").text if result.find(".//port") is not None else "",
                    "severity": result.find(".//severity").text if result.find(".//severity") is not None else "",
                    "description": result.find(".//description").text if result.find(".//description") is not None else "",
                    "cve": result.find(".//cve").text if result.find(".//cve") is not None else "",
                    "solution": result.find(".//solution").text if result.find(".//solution") is not None else "",
                    "nvt_oid": result.find(".//nvt").get("oid") if result.find(".//nvt") is not None else ""
                }
                results["vulnerabilities"].append(vuln)
            
            self.logger.info(f"OpenVAS scan completed. Found {len(results['vulnerabilities'])} vulnerabilities.")
            self.logger.info(f"Results are available in the Greenbone web interface (Task ID: {task_id})")
            return results
            
        except Exception as e:
            self.logger.error(f"OpenVAS scan failed: {str(e)}")
            return {"error": f"OpenVAS scan failed: {str(e)}"}
    
    def scan_with_nmap(self):
        """
        Perform a vulnerability scan using nmap NSE scripts.
        
        Returns:
            dict: Scan results
        """
        self.logger.info(f"Starting nmap vulnerability scan on {self.target}")
        
        try:
            # Build the nmap command with NSE scripts
            cmd = [
                "nmap", "-sV", "--script=vuln", "-oX", "-",  # Output in XML format to stdout
                self.target
            ]
            
            # Run the nmap scan
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Nmap scan failed: {stderr.decode()}")
                return {"error": f"Nmap scan failed: {stderr.decode()}"}
            
            # Parse the XML output
            root = ET.fromstring(stdout.decode())
            
            # Initialize results
            results = {
                "scan_info": {
                    "scanner": "nmap",
                    "scan_start": root.get("start", ""),
                    "scan_end": root.get("end", ""),
                    "target": self.target,
                    "scan_config": "nmap_vuln"
                },
                "vulnerabilities": []
            }
            
            # Parse each host
            for host in root.findall(".//host"):
                host_ip = host.find(".//address[@addrtype='ipv4']").get("addr", "")
                
                # Parse each port
                for port in host.findall(".//port"):
                    port_id = port.get("portid", "")
                    protocol = port.get("protocol", "")
                    
                    # Parse service information
                    service = port.find("service")
                    service_name = service.get("name", "") if service is not None else ""
                    service_version = service.get("version", "") if service is not None else ""
                    
                    # Parse script results
                    for script in port.findall(".//script"):
                        script_id = script.get("id", "")
                        script_output = script.get("output", "")
                        
                        # Create vulnerability entry
                        vuln = {
                            "name": f"{script_id} - {service_name}",
                            "host": host_ip,
                            "port": f"{port_id}/{protocol}",
                            "severity": "Unknown",  # Nmap doesn't provide severity levels
                            "description": script_output,
                            "service": service_name,
                            "version": service_version
                        }
                        results["vulnerabilities"].append(vuln)
            
            self.logger.info(f"Nmap vulnerability scan completed. Found {len(results['vulnerabilities'])} potential vulnerabilities.")
            return results
            
        except Exception as e:
            self.logger.exception(f"Error during nmap vulnerability scanning: {str(e)}")
            return {"error": f"Error during nmap vulnerability scanning: {str(e)}"}
    
    def scan(self):
        """
        Perform vulnerability scanning based on configuration.
        
        Returns:
            dict: Scan results
        """
        if self.use_nmap:
            self.logger.info("Using nmap for vulnerability scanning")
            return self.scan_with_nmap()
        else:
            self.logger.info("Using OpenVAS for vulnerability scanning")
            return self.scan_with_openvas()
    
    def get_cve_details(self, cve_id):
        """
        Get details for a specific CVE ID.
        
        Args:
            cve_id (str): The CVE ID to look up
        
        Returns:
            dict: CVE details
        """
        try:
            # Try to get CVE details from the NIST NVD API
            import requests
            api_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
            response = requests.get(api_url)
            
            if response.status_code == 200:
                data = response.json()
                if "result" in data:
                    cve_item = data["result"]["CVE_Items"][0]
                    return {
                        "id": cve_id,
                        "description": cve_item["cve"]["description"]["description_data"][0]["value"],
                        "severity": cve_item["impact"]["baseMetricV2"]["severity"] if "baseMetricV2" in cve_item["impact"] else "N/A",
                        "cvss_score": cve_item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"] if "baseMetricV2" in cve_item["impact"] else "N/A",
                        "published_date": cve_item["publishedDate"],
                        "last_modified": cve_item["lastModifiedDate"]
                    }
            
            # If API request fails, return basic info
            return {"id": cve_id, "description": "Details not available", "severity": "N/A"}
            
        except Exception as e:
            self.logger.warning(f"Error retrieving CVE details for {cve_id}: {str(e)}")
            return {"id": cve_id, "description": "Details not available", "severity": "N/A"} 