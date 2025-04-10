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
import shlex

logger = logging.getLogger(__name__)

class AdaptiveScanner:
    def __init__(self, target: str):
        self.target = target
        # Get scan results directory from environment var or use default
        self.scan_results_dir = os.getenv('SCAN_RESULTS_DIR', 'scan_results')
        
        # Ensure scan_results_dir is an absolute path if possible
        if not os.path.isabs(self.scan_results_dir) and 'INSTALL_DIR' in os.environ:
            self.scan_results_dir = os.path.join(os.environ['INSTALL_DIR'], self.scan_results_dir)
            
        # Create the scan results directory if it doesn't exist
        try:
            os.makedirs(self.scan_results_dir, exist_ok=True)
            logger.info(f"Using scan results directory: {self.scan_results_dir}")
        except Exception as e:
            logger.warning(f"Failed to create scan results directory: {str(e)}")
            # Fall back to current directory/scan_results if we can't create the configured one
            fallback_dir = os.path.join(os.getcwd(), 'scan_results')
            try:
                os.makedirs(fallback_dir, exist_ok=True)
                self.scan_results_dir = fallback_dir
                logger.info(f"Using fallback scan results directory: {self.scan_results_dir}")
            except Exception as fallback_error:
                logger.error(f"Failed to create fallback scan results directory: {str(fallback_error)}")
                # Last resort, just use the current directory
                self.scan_results_dir = os.getcwd()
                logger.warning(f"Using current directory for scan results: {self.scan_results_dir}")
        
        self.workspace = "AI_MAL_workspace"

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
        Perform an adaptive scan based on the provided parameters.
        If a scan fails, it will retry with different parameters, MAC address, and IP.
        """
        print(f"Starting adaptive scan on target: {self.target}")
        print(f"Scan parameters: stealth={stealth}, services={services}, version={version}, OS detection={os_detection}, vuln scan={vuln_scan}")
        
        max_retries = 3
        retry_count = 0
        original_mac = None
        
        # First check if nmap is installed
        try:
            print("Checking if nmap is installed...")
            nmap_check = await asyncio.create_subprocess_exec(
                'nmap', '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            nmap_out, nmap_err = await nmap_check.communicate()
            
            if nmap_check.returncode != 0:
                logger.error("Nmap is not installed or not in PATH")
                print("ERROR: Nmap is not installed or not in PATH")
                raise Exception("Nmap is not installed or not in PATH. Please install nmap before running AI_MAL.")
            else:
                nmap_version = nmap_out.decode().strip().split('\n')[0]
                logger.info(f"Using {nmap_version}")
                print(f"Using {nmap_version}")
        except FileNotFoundError:
            logger.error("Nmap executable not found")
            print("ERROR: Nmap executable not found")
            raise Exception("Nmap executable not found. Please install nmap before running AI_MAL.")
        
        try:
            # Save original MAC address if we can get it
            original_mac = await self._get_current_mac()
            
            while retry_count < max_retries:
                try:
                    # Build nmap command based on parameters
                    nmap_args = ['nmap']
                    
                    # Always run with privileged options since we're running as root
                    nmap_args.append('--privileged')
                    
                    # Skip ping scan if target is unreachable
                    nmap_args.append('-Pn')
                    
                    # Add host timeout to prevent hanging
                    nmap_args.extend(['--host-timeout', '120s'])
                    
                    # Adjust parameters based on retry count
                    if retry_count > 0:
                        logger.info(f"Scan attempt {retry_count+1} - Adapting scan parameters...")
                        
                        # For first retry, try more stealth approach
                        if retry_count == 1:
                            stealth = True
                            logger.info("Using stealth scan parameters")
                        
                        # For second retry, try different timing and techniques
                        elif retry_count == 2:
                            nmap_args.extend(['-T2', '-f', '--data-length', '24', '--randomize-hosts'])
                            logger.info("Using fragmented packets and randomization")
                    
                    # Apply scan parameters
                    if stealth:
                        nmap_args.extend(['-sS', '-T2', '--randomize-hosts'])
                    else:
                        nmap_args.extend(['-sV', '-sC'])
                    
                    if services:
                        nmap_args.append('-sV')
                    if version:
                        nmap_args.append('--version-intensity=5')
                    if os_detection:
                        nmap_args.append('-O')
                    if vuln_scan:
                        nmap_args.append('--script=vuln')
                    
                    # DoS-specific options
                    if dos:
                        # Use DoS-related NSE scripts for testing service resilience
                        dos_scripts = [
                            'dos', 
                            'syn-flood', 
                            'http-slowloris', 
                            'http-flood'
                        ]
                        nmap_args.append(f'--script={",".join(dos_scripts)}')
                        # Increase aggressiveness for DoS testing
                        nmap_args.append('-T5')
                        # Increase packet rate for stress testing
                        nmap_args.append('--min-rate=1000')
                        # Log what we're doing
                        logger.warning("Running DoS testing scripts against target - USE WITH CAUTION!")
                    else:
                        # Standard scan limit retries to reduce network load
                        nmap_args.append('--max-retries=1')
                    
                    # For retries, add decoy IP addresses
                    if retry_count > 0:
                        decoys = self._generate_decoy_ips(3)
                        nmap_args.append(f'-D{",".join(decoys)}')
                        
                        # Change MAC address for retry scans
                        if original_mac:
                            new_mac = self._generate_random_mac()
                            logger.info(f"Changing MAC address to {new_mac}")
                            await self._change_mac_address(new_mac)
                    
                    # Always add target (and ensure it's properly escaped)
                    escaped_target = shlex.quote(self.target)
                    nmap_args.append(escaped_target)
                    
                    # Add verbose flag for better logging
                    nmap_args.append('-v')
                    
                    # Run nmap scan
                    cmd_str = ' '.join(nmap_args)
                    logger.info(f"Starting scan with command: {cmd_str}")
                    print(f"Starting nmap scan with command: {cmd_str}")
                    print("This may take some time depending on the scan options...")
                    
                    scan_start_time = datetime.now()
                    try:
                        # Create process with explicit streaming of stdout and stderr 
                        process = await asyncio.create_subprocess_exec(
                            *nmap_args,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            limit=1024*1024  # Increase buffer size to 1MB
                        )
                        
                        print(f"Nmap scan in progress... (PID: {process.pid})")
                        
                        # Set up a progress reporter task
                        async def report_progress():
                            progress_shown = False
                            interval = 5  # Update every 5 seconds initially
                            while True:
                                await asyncio.sleep(interval)
                                elapsed = (datetime.now() - scan_start_time).seconds
                                
                                # Reduce update interval after 30 seconds for less spam
                                if elapsed > 30 and interval == 5:
                                    interval = 10
                                
                                # Try to get partial results from nmap process
                                message = f"Scan in progress... ({elapsed} seconds elapsed)"
                                
                                # After 30 seconds, provide more detailed information
                                if elapsed > 30 and not progress_shown:
                                    message += "\nStill scanning. For faster results, try:"
                                    message += "\n1. Check target is reachable (ping it first)"
                                    message += "\n2. Use fewer scan options"
                                    message += "\n3. Press Ctrl+C to cancel the scan if it's taking too long"
                                    progress_shown = True
                                
                                print(message)
                        
                        # Start the progress reporter
                        progress_reporter = asyncio.create_task(report_progress())
                        
                        try:
                            stdout, stderr = await process.communicate()
                            # Cancel progress reporter
                            progress_reporter.cancel()
                        except asyncio.CancelledError:
                            # Handle task cancellation
                            progress_reporter.cancel()
                            raise
                        
                        print(f"Nmap scan completed in {(datetime.now() - scan_start_time).seconds} seconds")
                        
                        # Log stdout and stderr for debugging
                        logger.debug(f"Nmap stdout: {stdout.decode()}")
                        if stderr:
                            logger.debug(f"Nmap stderr: {stderr.decode()}")
                            print(f"Nmap stderr: {stderr.decode()}")
                        
                        if process.returncode != 0:
                            error_msg = stderr.decode()
                            logger.warning(f"Scan attempt {retry_count+1} failed: {error_msg}")
                            print(f"Scan attempt {retry_count+1} failed: {error_msg}")
                            
                            if retry_count == max_retries - 1:
                                # Last attempt failed, raise exception
                                logger.error(f"All scan attempts failed. Last error: {error_msg}")
                                print(f"All scan attempts failed. Last error: {error_msg}")
                                raise Exception(f"Nmap scan failed after {max_retries} attempts: {error_msg}")
                            
                            # Increment retry counter and continue to next attempt
                            retry_count += 1
                            continue
                        
                        # Check if stdout is empty
                        if not stdout:
                            logger.warning("Nmap returned empty output, possible permission issue or no results")
                            if retry_count == max_retries - 1:
                                raise Exception("Nmap returned empty output. Check if running with sufficient permissions.")
                            retry_count += 1
                            continue
                        
                        # Scan successful, parse results
                        logger.info(f"Scan successful on attempt {retry_count+1}")
                        results = self._parse_nmap_output(stdout.decode())
                        
                        # If DoS scanning was requested, perform additional DoS testing
                        if dos and results.get('hosts'):
                            logger.warning("Performing additional DoS testing against discovered services...")
                            dos_results = await self._perform_additional_dos_tests(results)
                            
                            # Add DoS test results to the main results
                            for host in results.get('hosts', []):
                                host['dos_tests'] = dos_results.get(host.get('ip'), {})
                        
                        # Save results
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        output_file = os.path.join(self.scan_results_dir, f'scan_{timestamp}.json')
                        
                        with open(output_file, 'w') as f:
                            json.dump(results, f, indent=2)
                        
                        logger.info(f"Scan results saved to {output_file}")
                        
                        # Restore original MAC address if we changed it
                        if retry_count > 0 and original_mac:
                            logger.info(f"Restoring original MAC address: {original_mac}")
                            await self._change_mac_address(original_mac)
                        
                        return results
                    except FileNotFoundError:
                        logger.error("Nmap executable not found. Please make sure nmap is installed and in PATH.")
                        raise Exception("Nmap executable not found. Please install nmap before running AI_MAL.")
                    except asyncio.TimeoutError:
                        logger.warning("The scan timed out. Trying shell execution as fallback...")
                        print("Asyncio subprocess timed out. Trying direct shell command...")
                        
                        # Fallback to direct shell execution using subprocess
                        try:
                            # Capture scan start time
                            fallback_start_time = datetime.now()
                            
                            # Run nmap using subprocess with a timeout
                            cmd_str = ' '.join(nmap_args)
                            print(f"Running fallback shell command: {cmd_str}")
                            
                            process = subprocess.run(
                                cmd_str, 
                                shell=True, 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE,
                                timeout=600  # 10 minute timeout
                            )
                            
                            # Process output from shell execution
                            stdout = process.stdout
                            stderr = process.stderr
                            
                            elapsed = (datetime.now() - fallback_start_time).seconds
                            print(f"Fallback shell scan completed in {elapsed} seconds")
                            
                            # Rest of the processing remains the same as above...
                            if process.returncode != 0:
                                error_msg = stderr.decode()
                                logger.warning(f"Fallback scan attempt failed: {error_msg}")
                                print(f"Fallback scan attempt failed: {error_msg}")
                                raise Exception(f"Nmap scan failed: {error_msg}")
                            
                            # Check if stdout is empty
                            if not stdout:
                                logger.warning("Nmap returned empty output")
                                raise Exception("Nmap returned empty output")
                            
                            # Scan successful, parse results
                            logger.info("Fallback shell scan successful")
                            results = self._parse_nmap_output(stdout.decode())
                            
                            # Save and return results as before
                            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                            output_file = os.path.join(self.scan_results_dir, f'scan_{timestamp}.json')
                            
                            with open(output_file, 'w') as f:
                                json.dump(results, f, indent=2)
                            
                            logger.info(f"Scan results saved to {output_file}")
                            return results
                            
                        except subprocess.TimeoutExpired:
                            logger.error("Fallback shell execution also timed out")
                            print("Fallback scan timed out as well. Target may be unreachable.")
                            raise Exception("Nmap scan timed out. Target may be unreachable.")
                        except Exception as e:
                            logger.error(f"Error in fallback shell execution: {str(e)}")
                            print(f"Error in fallback shell execution: {str(e)}")
                            raise
                except Exception as e:
                    logger.warning(f"Error during scan attempt {retry_count+1}: {str(e)}")
                    retry_count += 1
                    
                    if retry_count >= max_retries:
                        raise
                    
                    # Wait before retrying
                    await asyncio.sleep(2)
            
            # Should not reach here, but just in case
            raise Exception(f"Nmap scan failed after {max_retries} attempts")
                
        except Exception as e:
            logger.error(f"Fatal error during scan: {str(e)}")
            
            # Ensure MAC address is restored
            if original_mac:
                try:
                    await self._change_mac_address(original_mac)
                except:
                    pass
            
            raise
    
    async def _get_current_mac(self) -> Optional[str]:
        """Get the current MAC address of the primary interface"""
        try:
            # Try to find the primary interface first
            interface = await self._get_primary_interface()
            if not interface:
                return None
                
            # Get the MAC address of the interface
            cmd = ['ip', 'link', 'show', interface]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            output = stdout.decode()
            
            # Extract MAC address using regex
            mac_match = re.search(r'link/ether ([0-9a-f:]{17})', output)
            if mac_match:
                return mac_match.group(1)
                
            return None
        except Exception as e:
            logger.warning(f"Failed to get current MAC address: {str(e)}")
            return None
    
    async def _get_primary_interface(self) -> Optional[str]:
        """Get the name of the primary network interface"""
        try:
            # Check the route to determine the primary interface
            cmd = ['ip', 'route', 'get', '8.8.8.8']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            output = stdout.decode()
            
            # Extract interface name using regex
            interface_match = re.search(r'dev\s+(\w+)', output)
            if interface_match:
                return interface_match.group(1)
                
            return None
        except Exception as e:
            logger.warning(f"Failed to get primary interface: {str(e)}")
            return None
    
    def _generate_random_mac(self) -> str:
        """Generate a random MAC address"""
        import random
        
        # Generate a random MAC address
        mac = [random.randint(0x00, 0xff) for _ in range(6)]
        
        # Set the locally administered bit
        mac[0] = (mac[0] & 0xfc) | 0x02
        
        # Format as MAC address
        return ':'.join([f'{b:02x}' for b in mac])
    
    async def _change_mac_address(self, mac: str) -> bool:
        """Change the MAC address of the primary interface"""
        try:
            interface = await self._get_primary_interface()
            if not interface:
                logger.warning("Cannot change MAC: No primary interface found")
                return False
                
            # Need to bring interface down, change MAC, then bring it back up
            cmd_down = ['ip', 'link', 'set', 'dev', interface, 'down']
            cmd_change = ['ip', 'link', 'set', 'dev', interface, 'address', mac]
            cmd_up = ['ip', 'link', 'set', 'dev', interface, 'up']
            
            # Execute commands
            for cmd in [cmd_down, cmd_change, cmd_up]:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                _, stderr = await process.communicate()
                
                if process.returncode != 0:
                    logger.warning(f"MAC change command failed: {stderr.decode()}")
                    return False
            
            logger.info(f"Successfully changed MAC address to {mac}")
            return True
        except Exception as e:
            logger.warning(f"Failed to change MAC address: {str(e)}")
            return False
    
    def _generate_decoy_ips(self, count: int) -> List[str]:
        """Generate random decoy IP addresses"""
        import random
        
        decoys = []
        for _ in range(count):
            # Generate random IP address
            ip = '.'.join(str(random.randint(1, 254)) for _ in range(4))
            decoys.append(ip)
            
        return decoys

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
        lines = output.strip().split('\n')
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

    async def _perform_additional_dos_tests(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform additional DoS testing against discovered services
        """
        results = {}
        
        for host in scan_results.get('hosts', []):
            host_ip = host.get('ip')
            if not host_ip:
                continue
                
            host_results = {}
            
            # Test each open port for DoS vulnerabilities
            for port in host.get('ports', []):
                port_num = port.get('port')
                service = port.get('service', '')
                if not port_num or port.get('state') != 'open':
                    continue
                
                service_results = {}
                
                # HTTP-based DoS tests
                if service.lower() in ['http', 'https'] or port_num in [80, 443, 8080, 8443]:
                    logger.warning(f"Testing HTTP DoS vulnerabilities on {host_ip}:{port_num}")
                    
                    # Perform HTTP Slowloris test
                    slowloris_result = await self._test_slowloris(host_ip, port_num)
                    service_results['slowloris'] = slowloris_result
                    
                    # Perform HTTP Flood test
                    http_flood_result = await self._test_http_flood(host_ip, port_num)
                    service_results['http_flood'] = http_flood_result
                
                # TCP SYN flood test for any service
                logger.warning(f"Testing SYN flood vulnerability on {host_ip}:{port_num}")
                syn_flood_result = await self._test_syn_flood(host_ip, port_num)
                service_results['syn_flood'] = syn_flood_result
                
                host_results[str(port_num)] = service_results
            
            results[host_ip] = host_results
            
        return results
        
    async def _test_slowloris(self, target: str, port: int) -> Dict[str, Any]:
        """
        Test target for HTTP Slowloris vulnerability
        """
        try:
            # Use a limited version for testing purposes - don't actually take down the service
            # Just check if it's vulnerable
            cmd = [
                'nmap',
                '--script=http-slowloris',
                '--script-args=http-slowloris.runforever=false,http-slowloris.timeout=10',
                '-p', str(port),
                target
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode()
            
            # Parse results to determine vulnerability
            vulnerable = 'VULNERABLE' in output
            
            return {
                "test": "slowloris",
                "vulnerable": vulnerable,
                "details": output if vulnerable else "Not vulnerable to Slowloris"
            }
            
        except Exception as e:
            logger.error(f"Error during Slowloris test: {str(e)}")
            return {
                "test": "slowloris",
                "vulnerable": False,
                "error": str(e)
            }
    
    async def _test_http_flood(self, target: str, port: int) -> Dict[str, Any]:
        """
        Test target for HTTP flood vulnerability
        """
        try:
            # Simulate an HTTP flood with limited requests
            protocol = 'https' if port == 443 else 'http'
            cmd = [
                'ab',  # Apache Benchmark tool
                '-n', '1000',  # Number of requests
                '-c', '50',    # Concurrency
                '-k',          # Keep-alive
                f'{protocol}://{target}:{port}/'
            ]
            
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate(timeout=15)  # Limit test time
                output = stdout.decode()
                
                # Analyze response times and errors to determine vulnerability
                failed_requests = re.search(r'Failed requests:\s+(\d+)', output)
                if failed_requests and int(failed_requests.group(1)) > 0:
                    vulnerable = True
                    details = f"Server failed to handle {failed_requests.group(1)} requests"
                else:
                    vulnerable = False
                    details = "Server handled all test requests"
                
                return {
                    "test": "http_flood",
                    "vulnerable": vulnerable,
                    "details": details
                }
                
            except asyncio.TimeoutError:
                # If the command timed out, the server might be vulnerable
                return {
                    "test": "http_flood",
                    "vulnerable": True,
                    "details": "Server response time degraded significantly during test"
                }
                
        except Exception as e:
            logger.error(f"Error during HTTP flood test: {str(e)}")
            return {
                "test": "http_flood",
                "vulnerable": False,
                "error": str(e)
            }
    
    async def _test_syn_flood(self, target: str, port: int) -> Dict[str, Any]:
        """
        Test target for SYN flood vulnerability
        """
        try:
            # Use hping3 for a controlled SYN flood test
            cmd = [
                'hping3',
                '-S',          # SYN flag
                '-p', str(port),
                '--flood',      # Flood mode
                '--rand-source', # Random source IP
                '-c', '1000',   # Packet count - limited for testing
                target
            ]
            
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate(timeout=10)  # Limit test time
                output = stdout.decode()
                
                # After the flood, check if service is still responsive
                responsive = await self._check_port_responsive(target, port)
                
                if responsive:
                    return {
                        "test": "syn_flood",
                        "vulnerable": False,
                        "details": "Service remained responsive during SYN flood"
                    }
                else:
                    return {
                        "test": "syn_flood",
                        "vulnerable": True,
                        "details": "Service became unresponsive during SYN flood"
                    }
                    
            except asyncio.TimeoutError:
                # Command timeout could indicate the test was successful in affecting the service
                responsive = await self._check_port_responsive(target, port)
                return {
                    "test": "syn_flood",
                    "vulnerable": not responsive,
                    "details": "Test timed out, service responsiveness: " + ("No" if not responsive else "Yes")
                }
                
        except Exception as e:
            logger.error(f"Error during SYN flood test: {str(e)}")
            return {
                "test": "syn_flood",
                "vulnerable": False,
                "error": str(e)
            }
    
    async def _check_port_responsive(self, target: str, port: int) -> bool:
        """
        Check if a port is responsive after DoS testing
        """
        try:
            # Use a simple socket connection to check responsiveness
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Short timeout
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False 