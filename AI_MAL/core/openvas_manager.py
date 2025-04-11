#!/usr/bin/env python3
"""
OpenVAS Manager module for interaction with OpenVAS/Greenbone Vulnerability Scanner
"""

import os
import subprocess
import time
import json
import xml.etree.ElementTree as ET
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
import socket
import re
import asyncio
import aiohttp
from datetime import datetime

logger = logging.getLogger("AI_MAL.openvas_manager")

class OpenVASManager:
    """
    Class for handling interaction with OpenVAS/Greenbone Vulnerability Scanner.
    This class provides methods to set up, configure, and run scans using OpenVAS.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the OpenVAS manager with the given configuration.
        
        Args:
            config: Configuration dictionary with scan parameters
        """
        self.config = config or {}
        self.gvm_socket_path = "/var/run/gvmd/gvmd.sock"
        self.omp_path = "omp"  # Default OMP path
        self.openvas_path = "openvas"  # Default OpenVAS path
        self.gvm_user = self.config.get("gvm_user", "admin")
        self.gvm_password = self.config.get("gvm_password", None)
        self.scan_results_dir = Path(self.config.get("results_dir", "scan_results"))
        
        # Create results directory if it doesn't exist
        os.makedirs(self.scan_results_dir, exist_ok=True)
        
        # Initialize API authentication if configured
        self.gsa_api_url = self.config.get("gsa_api_url", "https://127.0.0.1:9392")
        self.gsa_username = self.config.get("gsa_username", "admin")
        self.gsa_password = self.config.get("gsa_password", None)
        self.api_token = None
        
    async def check_openvas_status(self) -> Dict[str, Any]:
        """
        Check if OpenVAS is installed and services are running.
        
        Returns:
            Dictionary with status information
        """
        status = {
            "installed": False,
            "openvas_running": False,
            "redis_running": False,
            "gvmd_running": False,
            "gsad_running": False,
            "ospd_openvas_running": False,
            "feed_status": None,
            "version": None
        }
        
        try:
            # Check if OpenVAS is installed
            result = subprocess.run(
                ["openvas", "--version"], 
                capture_output=True, 
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                status["installed"] = True
                # Extract version from output
                version_match = re.search(r"OpenVAS (\d+\.\d+\.\d+)", result.stdout)
                if version_match:
                    status["version"] = version_match.group(1)
                    
            # Check if Redis is running (required for OpenVAS)
            redis_check = subprocess.run(
                ["redis-cli", "ping"], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            status["redis_running"] = redis_check.returncode == 0 and "PONG" in redis_check.stdout
            
            # Check if gvmd is running
            gvmd_check = subprocess.run(
                ["ps", "aux"], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            status["gvmd_running"] = "gvmd" in gvmd_check.stdout
            
            # Check if gsad (Greenbone Security Assistant) is running
            gsad_check = subprocess.run(
                ["ps", "aux"], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            status["gsad_running"] = "gsad" in gsad_check.stdout
            
            # Check if ospd-openvas is running
            ospd_check = subprocess.run(
                ["ps", "aux"], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            status["ospd_openvas_running"] = "ospd-openvas" in ospd_check.stdout
            
            # Check feed status
            if status["installed"]:
                feed_check = subprocess.run(
                    ["greenbone-feed-sync", "--feedstatus"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if feed_check.returncode == 0:
                    status["feed_status"] = feed_check.stdout.strip()
                else:
                    status["feed_status"] = "Unable to determine feed status"
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout while checking OpenVAS status")
        except FileNotFoundError:
            logger.warning("OpenVAS commands not found in PATH")
        except Exception as e:
            logger.error(f"Error while checking OpenVAS status: {str(e)}")
            
        # Determine overall openvas_running status
        status["openvas_running"] = (status["redis_running"] and 
                                    status["gvmd_running"] and 
                                    status["ospd_openvas_running"])
        
        return status
        
    async def start_openvas_services(self) -> bool:
        """
        Start all required OpenVAS services.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Start Redis if not running
            status = await self.check_openvas_status()
            if not status["redis_running"]:
                logger.info("Starting Redis service...")
                subprocess.run(
                    ["sudo", "systemctl", "start", "redis-server@openvas.service"],
                    check=True,
                    timeout=30
                )
            
            # Start gvmd if not running
            if not status["gvmd_running"]:
                logger.info("Starting gvmd service...")
                subprocess.run(
                    ["sudo", "systemctl", "start", "gvmd"],
                    check=True,
                    timeout=30
                )
            
            # Start ospd-openvas if not running
            if not status["ospd_openvas_running"]:
                logger.info("Starting ospd-openvas service...")
                subprocess.run(
                    ["sudo", "systemctl", "start", "ospd-openvas"],
                    check=True,
                    timeout=30
                )
            
            # Start gsad if not running
            if not status["gsad_running"]:
                logger.info("Starting gsad service...")
                subprocess.run(
                    ["sudo", "systemctl", "start", "gsad"],
                    check=True,
                    timeout=30
                )
            
            # Wait for services to start
            logger.info("Waiting for OpenVAS services to initialize...")
            await asyncio.sleep(10)
            
            # Verify that services are running
            status = await self.check_openvas_status()
            if status["openvas_running"]:
                logger.info("All OpenVAS services started successfully")
                return True
            else:
                logger.error("Failed to start all OpenVAS services")
                return False
                
        except subprocess.SubprocessError as e:
            logger.error(f"Error starting OpenVAS services: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error starting OpenVAS services: {str(e)}")
            return False
    
    async def stop_openvas_services(self) -> bool:
        """
        Stop all OpenVAS services.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Stop services in reverse order
            logger.info("Stopping gsad service...")
            subprocess.run(
                ["sudo", "systemctl", "stop", "gsad"],
                check=True,
                timeout=30
            )
            
            logger.info("Stopping ospd-openvas service...")
            subprocess.run(
                ["sudo", "systemctl", "stop", "ospd-openvas"],
                check=True,
                timeout=30
            )
            
            logger.info("Stopping gvmd service...")
            subprocess.run(
                ["sudo", "systemctl", "stop", "gvmd"],
                check=True,
                timeout=30
            )
            
            logger.info("Stopping Redis service...")
            subprocess.run(
                ["sudo", "systemctl", "stop", "redis-server@openvas.service"],
                check=True,
                timeout=30
            )
            
            # Verify services are stopped
            logger.info("Verifying OpenVAS services stopped...")
            await asyncio.sleep(5)
            status = await self.check_openvas_status()
            if not status["openvas_running"]:
                logger.info("All OpenVAS services stopped successfully")
                return True
            else:
                logger.error("Failed to stop all OpenVAS services")
                return False
                
        except subprocess.SubprocessError as e:
            logger.error(f"Error stopping OpenVAS services: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error stopping OpenVAS services: {str(e)}")
            return False
    
    async def update_feeds(self) -> bool:
        """
        Update OpenVAS NVT, SCAP and CERT feeds.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info("Updating OpenVAS feeds. This may take a while...")
            
            # Run greenbone-feed-sync to update all feeds
            process = subprocess.run(
                ["sudo", "greenbone-feed-sync"],
                check=True,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes timeout
            )
            
            logger.info("OpenVAS feeds updated successfully")
            return True
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout while updating OpenVAS feeds")
            return False
        except subprocess.SubprocessError as e:
            logger.error(f"Error updating OpenVAS feeds: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error updating OpenVAS feeds: {str(e)}")
            return False
    
    async def create_target(self, target_ip: str, target_name: str = None) -> Optional[str]:
        """
        Create a scan target in OpenVAS.
        
        Args:
            target_ip: IP address or hostname to scan
            target_name: Name for the target (defaults to IP if not provided)
            
        Returns:
            Target ID if successful, None otherwise
        """
        if not target_name:
            target_name = f"AI_MAL-Target-{target_ip}"
            
        try:
            # Create target using omp command
            target_cmd = [
                "omp",
                "--xml=<create_target>"
                f"<name>{target_name}</name>"
                f"<hosts>{target_ip}</hosts>"
                "<port_list id=\"33d0cd82-57c6-11e1-8ed1-406186ea4fc5\"/>"  # Default port list
                "</create_target>"
            ]
            
            result = subprocess.run(
                target_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Extract target ID from response
                match = re.search(r'id="([a-zA-Z0-9-]+)"', result.stdout)
                if match:
                    target_id = match.group(1)
                    logger.info(f"Target created successfully with ID: {target_id}")
                    return target_id
            
            logger.error(f"Failed to create target: {result.stderr}")
            return None
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error creating target: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error creating target: {str(e)}")
            return None
    
    async def create_task(self, target_id: str, task_name: str = None, 
                         scan_config_id: str = "daba56c8-73ec-11df-a475-002264764cea") -> Optional[str]:
        """
        Create a scan task in OpenVAS.
        
        Args:
            target_id: ID of the target to scan
            task_name: Name for the task (defaults to timestamp if not provided)
            scan_config_id: ID of the scan configuration to use
                            (default is Full and fast)
            
        Returns:
            Task ID if successful, None otherwise
        """
        if not task_name:
            task_name = f"AI_MAL-Scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            
        try:
            # Create task using omp command
            task_cmd = [
                "omp",
                "--xml=<create_task>"
                f"<name>{task_name}</name>"
                "<comment>Created by AI_MAL</comment>"
                f"<config id=\"{scan_config_id}\"/>"
                f"<target id=\"{target_id}\"/>"
                "<scanner id=\"08b69003-5fc2-4037-a479-93b440211c73\"/>"  # OpenVAS Default Scanner
                "</create_task>"
            ]
            
            result = subprocess.run(
                task_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Extract task ID from response
                match = re.search(r'id="([a-zA-Z0-9-]+)"', result.stdout)
                if match:
                    task_id = match.group(1)
                    logger.info(f"Task created successfully with ID: {task_id}")
                    return task_id
            
            logger.error(f"Failed to create task: {result.stderr}")
            return None
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error creating task: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error creating task: {str(e)}")
            return None
    
    async def start_task(self, task_id: str) -> Optional[str]:
        """
        Start a scan task in OpenVAS.
        
        Args:
            task_id: ID of the task to start
            
        Returns:
            Report ID if successful, None otherwise
        """
        try:
            # Start task using omp command
            start_cmd = [
                "omp",
                f"--xml=<start_task task_id=\"{task_id}\"/>"
            ]
            
            result = subprocess.run(
                start_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Extract report ID from response
                match = re.search(r'id="([a-zA-Z0-9-]+)"', result.stdout)
                if match:
                    report_id = match.group(1)
                    logger.info(f"Task started successfully, report ID: {report_id}")
                    return report_id
            
            logger.error(f"Failed to start task: {result.stderr}")
            return None
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error starting task: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error starting task: {str(e)}")
            return None
    
    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get the status of a scan task.
        
        Args:
            task_id: ID of the task to check
            
        Returns:
            Dictionary with task status information
        """
        try:
            # Get task status using omp command
            status_cmd = [
                "omp",
                f"--xml=<get_tasks task_id=\"{task_id}\" details=\"1\"/>"
            ]
            
            result = subprocess.run(
                status_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse XML response
                root = ET.fromstring(result.stdout)
                task = root.find('.//task')
                
                if task is not None:
                    status = task.find('.//status').text
                    progress = task.find('.//progress').text
                    
                    return {
                        "status": status,
                        "progress": int(progress) if progress is not None else 0,
                        "is_running": status == "Running"
                    }
            
            logger.error(f"Failed to get task status: {result.stderr}")
            return {"status": "Unknown", "progress": 0, "is_running": False}
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error getting task status: {str(e)}")
            return {"status": "Error", "progress": 0, "is_running": False}
        except Exception as e:
            logger.error(f"Unexpected error getting task status: {str(e)}")
            return {"status": "Error", "progress": 0, "is_running": False}
    
    async def wait_for_task(self, task_id: str, 
                           poll_interval: int = 10, 
                           timeout: int = 3600) -> bool:
        """
        Wait for a scan task to complete.
        
        Args:
            task_id: ID of the task to wait for
            poll_interval: Seconds between status checks
            timeout: Maximum seconds to wait
            
        Returns:
            True if task completed, False if timeout or error
        """
        start_time = time.time()
        
        while (time.time() - start_time) < timeout:
            status = await self.get_task_status(task_id)
            
            if status["status"] == "Done":
                logger.info(f"Task {task_id} completed successfully")
                return True
                
            elif status["status"] == "Stopped" or status["status"] == "Failed":
                logger.error(f"Task {task_id} {status['status']}")
                return False
                
            elif status["is_running"]:
                logger.info(f"Task {task_id} is running, progress: {status['progress']}%")
                await asyncio.sleep(poll_interval)
                
            else:
                logger.info(f"Task {task_id} is in status: {status['status']}")
                await asyncio.sleep(poll_interval)
        
        logger.error(f"Timeout waiting for task {task_id} to complete")
        return False
    
    async def get_report(self, report_id: str, format_id: str = "a994b278-1f62-11e1-96ac-406186ea4fc5") -> Optional[str]:
        """
        Get a scan report from OpenVAS.
        
        Args:
            report_id: ID of the report to retrieve
            format_id: Report format ID (default is XML)
            
        Returns:
            Report content if successful, None otherwise
        """
        try:
            # Get report using omp command
            report_cmd = [
                "omp",
                f"--xml=<get_reports report_id=\"{report_id}\" format_id=\"{format_id}\"/>"
            ]
            
            result = subprocess.run(
                report_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                # Report content should be in the response
                return result.stdout
            
            logger.error(f"Failed to get report: {result.stderr}")
            return None
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error getting report: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting report: {str(e)}")
            return None
    
    async def parse_xml_report(self, xml_report: str) -> Dict[str, Any]:
        """
        Parse an XML report into a structured format.
        
        Args:
            xml_report: XML report content
            
        Returns:
            Dictionary with parsed report data
        """
        try:
            # Parse XML report
            root = ET.fromstring(xml_report)
            report = root.find('.//report')
            
            if report is None:
                logger.error("Invalid report format, no report element found")
                return {"error": "Invalid report format"}
            
            # Extract basic information
            result = {
                "scan_start": report.find('.//scan_start').text if report.find('.//scan_start') is not None else None,
                "scan_end": report.find('.//scan_end').text if report.find('.//scan_end') is not None else None,
                "hosts": [],
                "vulnerabilities": []
            }
            
            # Extract hosts information
            for host in report.findall('.//host'):
                host_info = {
                    "ip": host.find('.//ip').text if host.find('.//ip') is not None else None,
                    "hostname": host.find('.//hostname').text if host.find('.//hostname') is not None else None,
                    "ports": []
                }
                
                # Extract port information
                for port in host.findall('.//port'):
                    port_info = {
                        "port": port.get('id'),
                        "protocol": port.find('.//protocol').text if port.find('.//protocol') is not None else None,
                        "service": port.find('.//service').text if port.find('.//service') is not None else None
                    }
                    host_info["ports"].append(port_info)
                    
                result["hosts"].append(host_info)
            
            # Extract vulnerability information
            for vuln in report.findall('.//result'):
                vuln_info = {
                    "name": vuln.find('.//name').text if vuln.find('.//name') is not None else None,
                    "severity": float(vuln.find('.//severity').text) if vuln.find('.//severity') is not None else 0,
                    "host": vuln.find('.//host').text if vuln.find('.//host') is not None else None,
                    "port": vuln.find('.//port').text if vuln.find('.//port') is not None else None,
                    "description": vuln.find('.//description').text if vuln.find('.//description') is not None else None,
                    "nvt": vuln.find('.//nvt').get('id') if vuln.find('.//nvt') is not None else None,
                    "cve": vuln.find('.//cve').text if vuln.find('.//cve') is not None else None,
                    "solution": vuln.find('.//solution').text if vuln.find('.//solution') is not None else None
                }
                result["vulnerabilities"].append(vuln_info)
            
            return result
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {str(e)}")
            return {"error": f"XML parsing error: {str(e)}"}
        except Exception as e:
            logger.error(f"Error parsing report: {str(e)}")
            return {"error": f"Error parsing report: {str(e)}"}
    
    async def save_report(self, report_id: str, 
                          format_id: str = "a994b278-1f62-11e1-96ac-406186ea4fc5", 
                          file_format: str = "xml") -> Optional[str]:
        """
        Save a scan report to a file.
        
        Args:
            report_id: ID of the report to save
            format_id: Report format ID
            file_format: File extension for the report
            
        Returns:
            Path to the saved report if successful, None otherwise
        """
        try:
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"openvas-report-{timestamp}.{file_format}"
            file_path = self.scan_results_dir / filename
            
            # Get report
            report_content = await self.get_report(report_id, format_id)
            if report_content is None:
                return None
                
            # Save report to file
            with open(file_path, 'w') as f:
                f.write(report_content)
                
            logger.info(f"Report saved to {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Error saving report: {str(e)}")
            return None
    
    async def scan(self, target: str, 
                  scan_name: str = None, 
                  scan_config: str = "full_and_fast") -> Dict[str, Any]:
        """
        Perform a complete OpenVAS scan.
        
        Args:
            target: IP address or hostname to scan
            scan_name: Name for the scan (optional)
            scan_config: Type of scan config to use
            
        Returns:
            Dictionary with scan results
        """
        # Map scan_config string to config ID
        config_map = {
            "full_and_fast": "daba56c8-73ec-11df-a475-002264764cea",
            "full_and_very_deep": "708f25c4-7489-11df-8094-002264764cea",
            "discovery": "8715c877-47a0-438d-98a3-27c7a6ab2196",
            "system_discovery": "bbca7412-a950-11e3-9109-406186ea4fc5",
            "host_discovery": "2d3f051c-55ba-11e3-bf43-406186ea4fc5"
        }
        scan_config_id = config_map.get(scan_config, "daba56c8-73ec-11df-a475-002264764cea")
        
        # Check if OpenVAS is running
        status = await self.check_openvas_status()
        if not status["openvas_running"]:
            logger.warning("OpenVAS is not running, attempting to start services")
            if not await self.start_openvas_services():
                return {"error": "Failed to start OpenVAS services"}
        
        # Prepare scan name if not provided
        if scan_name is None:
            scan_name = f"AI_MAL-{target}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Create target
        target_id = await self.create_target(target, f"{scan_name}-target")
        if target_id is None:
            return {"error": "Failed to create target"}
            
        # Create task
        task_id = await self.create_task(target_id, scan_name, scan_config_id)
        if task_id is None:
            return {"error": "Failed to create task"}
            
        # Start task
        report_id = await self.start_task(task_id)
        if report_id is None:
            return {"error": "Failed to start task"}
            
        # Wait for task to complete
        logger.info(f"Waiting for scan {scan_name} to complete...")
        if not await self.wait_for_task(task_id):
            return {"error": "Scan did not complete successfully"}
            
        # Get report
        xml_report = await self.get_report(report_id)
        if xml_report is None:
            return {"error": "Failed to retrieve report"}
            
        # Parse report
        parsed_report = await self.parse_xml_report(xml_report)
        
        # Save report to file
        report_file = await self.save_report(report_id)
        if report_file:
            parsed_report["report_file"] = report_file
            
        # Add metadata
        parsed_report["scan_name"] = scan_name
        parsed_report["scan_config"] = scan_config
        parsed_report["target"] = target
        parsed_report["target_id"] = target_id
        parsed_report["task_id"] = task_id
        parsed_report["report_id"] = report_id
        
        return parsed_report
    
    async def cleanup_scan(self, task_id: str, target_id: str) -> bool:
        """
        Clean up a scan by removing the task and target.
        
        Args:
            task_id: ID of the task to remove
            target_id: ID of the target to remove
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Remove task
            task_cmd = [
                "omp",
                f"--xml=<delete_task task_id=\"{task_id}\" ultimate=\"1\"/>"
            ]
            
            task_result = subprocess.run(
                task_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Remove target
            target_cmd = [
                "omp",
                f"--xml=<delete_target target_id=\"{target_id}\" ultimate=\"1\"/>"
            ]
            
            target_result = subprocess.run(
                target_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return task_result.returncode == 0 and target_result.returncode == 0
            
        except subprocess.SubprocessError as e:
            logger.error(f"Error cleaning up scan: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error cleaning up scan: {str(e)}")
            return False 