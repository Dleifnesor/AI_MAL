#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Data Exfiltration Module for AI_MAL
===================================

This module handles the exfiltration of data from compromised systems.
"""

import os
import logging
import random
from datetime import datetime

class DataExfiltration:
    """Class for handling data exfiltration from target systems."""

    def __init__(self, scan_results):
        """
        Initialize the DataExfiltration class.

        Args:
            scan_results (dict): Dictionary containing scan results
        """
        self.scan_results = scan_results
        self.logger = logging.getLogger('AI_MAL.exfiltration')
        self.output_dir = os.path.join("results", "exfiltration", 
                                     datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        os.makedirs(self.output_dir, exist_ok=True)

    def exfiltrate(self):
        """
        Attempt to exfiltrate data from compromised systems.

        Returns:
            dict: Results of the exfiltration attempts
        """
        self.logger.info("Starting data exfiltration process")
        
        # Initialize results structure
        results = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "target_hosts": [],
            "successful_exfiltrations": 0,
            "failed_exfiltrations": 0,
            "total_data_size": 0,
            "data_files": [],
            "summary": ""
        }
        
        # Check if we have exploited hosts to work with
        if 'exploits' not in self.scan_results:
            self.logger.warning("No exploitation data found. Run with --msf --exploit first.")
            results["summary"] = "No exploited hosts found for exfiltration"
            return results
        
        # Get list of successfully exploited hosts
        exploited_hosts = [e for e in self.scan_results.get('exploits', []) 
                          if e.get('status') == 'success']
        
        if not exploited_hosts:
            self.logger.warning("No successfully exploited hosts found")
            results["summary"] = "No successfully exploited hosts found"
            return results
        
        # Attempt exfiltration on each exploited host
        for host in exploited_hosts:
            host_ip = host.get('host', 'unknown')
            self.logger.info(f"Attempting exfiltration from {host_ip}")
            
            host_result = {
                "host": host_ip,
                "session_id": host.get('session_id', 'unknown'),
                "exfiltrated_files": [],
                "status": "failed"
            }
            
            # Attempt to gather sensitive files
            try:
                # Simulate exfiltration (in real implementation, this would use the msf session)
                exfiltrated_files = self._simulate_exfiltration(host)
                
                if exfiltrated_files:
                    host_result["exfiltrated_files"] = exfiltrated_files
                    host_result["status"] = "success"
                    host_result["total_size"] = sum(f.get('size', 0) for f in exfiltrated_files)
                    
                    results["successful_exfiltrations"] += 1
                    results["total_data_size"] += host_result["total_size"]
                    results["data_files"].extend(exfiltrated_files)
                else:
                    results["failed_exfiltrations"] += 1
            
            except Exception as e:
                self.logger.error(f"Error during exfiltration from {host_ip}: {str(e)}")
                host_result["error"] = str(e)
                results["failed_exfiltrations"] += 1
            
            results["target_hosts"].append(host_result)
        
        # Generate summary
        if results["successful_exfiltrations"] > 0:
            results["summary"] = f"Successfully exfiltrated data from {results['successful_exfiltrations']} hosts. " \
                               f"Total data size: {results['total_data_size']} bytes."
        else:
            results["summary"] = "Failed to exfiltrate data from any hosts."
        
        self.logger.info(results["summary"])
        return results

    def _simulate_exfiltration(self, host):
        """
        Simulate exfiltration from a host (for development/testing).
        
        In a real implementation, this would use the Metasploit session to
        actually exfiltrate files from the target.
        
        Args:
            host (dict): Host information including session ID
            
        Returns:
            list: List of exfiltrated files
        """
        # Common sensitive files to simulate exfiltration
        sensitive_files = [
            "/etc/passwd", "/etc/shadow", "C:\\Windows\\System32\\config\\SAM",
            "/home/user/.ssh/id_rsa", "C:\\Users\\Administrator\\Documents\\credentials.txt",
            "/var/www/html/config.php", "C:\\inetpub\\wwwroot\\web.config"
        ]
        
        exfiltrated = []
        
        # Randomly determine how many files were "found"
        num_files = random.randint(0, min(4, len(sensitive_files)))
        
        for _ in range(num_files):
            file_path = sensitive_files[random.randint(0, len(sensitive_files)-1)]
            
            # Don't add the same file twice
            if any(f["path"] == file_path for f in exfiltrated):
                continue
                
            file_size = random.randint(1024, 1024*1024)  # Random size between 1KB and 1MB
            
            # Create a simulated exfiltrated file
            output_file = os.path.join(
                self.output_dir, 
                f"{host.get('host', 'unknown')}_{os.path.basename(file_path)}"
            )
            
            # Just touch the file to create it
            with open(output_file, 'w') as f:
                f.write(f"# Simulated content of {file_path}\n")
                f.write(f"# This is a placeholder for actual exfiltrated data\n")
            
            exfiltrated.append({
                "path": file_path,
                "size": file_size,
                "local_path": output_file,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        
        return exfiltrated 