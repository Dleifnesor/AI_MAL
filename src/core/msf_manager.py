import os
import re
import time
import platform
import subprocess
import tempfile
import socket
from pathlib import Path
import psutil
from .logger import LoggerWrapper

class MSFManager:
    """Manages interaction with Metasploit Framework."""
    
    def __init__(self, msf_host="127.0.0.1", msf_port=55553, msf_user="msf", msf_pass="msf"):
        self.msf_host = msf_host
        self.msf_port = msf_port
        self.msf_user = msf_user
        self.msf_pass = msf_pass
        self.msfrpcd_process = None
        self.logger = LoggerWrapper("MSFManager")
        self.is_kali = self._is_kali()
    
    def _is_kali(self):
        """Check if running on Kali Linux."""
        if platform.system() != "Linux":
            return False
            
        try:
            # Check for Kali Linux in os-release
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r") as f:
                    content = f.read().lower()
                    if "kali" in content:
                        self.logger.info("Detected Kali Linux")
                        return True
        except Exception as e:
            self.logger.warning(f"Error checking OS type: {e}")
            
        return False
    
    def _find_msf_path(self):
        """Find the path to msfrpcd and msfconsole."""
        # Common paths on different distributions
        possible_paths = [
            # Kali Linux
            "/usr/bin/msfrpcd",
            "/usr/share/metasploit-framework/msfrpcd",
            # Other Linux distros
            "/opt/metasploit-framework/msfrpcd",
            "/usr/local/bin/msfrpcd"
        ]
        
        # First try the PATH
        try:
            which_result = subprocess.run(
                ["which", "msfrpcd"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            if which_result.returncode == 0:
                msfrpcd_path = which_result.stdout.strip()
                if os.path.exists(msfrpcd_path):
                    self.logger.info(f"Found msfrpcd in PATH: {msfrpcd_path}")
                    return msfrpcd_path
        except Exception as e:
            self.logger.warning(f"Error finding msfrpcd in PATH: {e}")
        
        # Then check common paths
        for path in possible_paths:
            if os.path.exists(path):
                self.logger.info(f"Found msfrpcd at: {path}")
                return path
                
        # If we can't find msfrpcd directly, try to find msfconsole and use the same directory
        try:
            which_console = subprocess.run(
                ["which", "msfconsole"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            if which_console.returncode == 0:
                msfconsole_path = which_console.stdout.strip()
                msf_dir = os.path.dirname(msfconsole_path)
                msfrpcd_path = os.path.join(msf_dir, "msfrpcd")
                if os.path.exists(msfrpcd_path):
                    self.logger.info(f"Found msfrpcd via msfconsole path: {msfrpcd_path}")
                    return msfrpcd_path
        except Exception as e:
            self.logger.warning(f"Error finding msfconsole path: {e}")
            
        # If all else fails on Kali, use ruby to run msfrpcd
        if self.is_kali:
            self.logger.info("Using ruby to run msfrpcd on Kali Linux")
            return "msfrpcd"  # Will use PATH and special handling
            
        self.logger.error("Could not find msfrpcd path")
        return None
    
    def is_available(self):
        """Check if Metasploit Framework is available."""
        try:
            # Check if msfconsole is available on the system
            which_result = subprocess.run(
                ["which", "msfconsole"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            if which_result.returncode != 0:
                self.logger.warning("Metasploit Framework not found on the system")
                return False
                
            self.logger.info("Metasploit Framework is available")
            return True
        except Exception as e:
            self.logger.error(f"Error checking Metasploit availability: {e}")
            return False
    
    def is_running(self):
        """Check if msfrpcd is already running."""
        try:
            # Check if port is in use
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                return s.connect_ex((self.msf_host, self.msf_port)) == 0
        except Exception as e:
            self.logger.error(f"Error checking if msfrpcd is running: {e}")
            return False
    
    def start_msfrpcd(self):
        """Start msfrpcd service."""
        if self.is_running():
            self.logger.info("msfrpcd is already running")
            return True
            
        self.logger.info(f"Starting msfrpcd on {self.msf_host}:{self.msf_port}")
        
        msfrpcd_path = self._find_msf_path()
        if not msfrpcd_path:
            self.logger.error("Could not find msfrpcd, cannot start service")
            return False
            
        try:
            # Construct the command based on the environment
            if self.is_kali and msfrpcd_path == "msfrpcd":
                # On Kali, msfrpcd may not be directly executable, use ruby
                cmd = [
                    "ruby", "/usr/share/metasploit-framework/msfrpcd",
                    "-U", self.msf_user,
                    "-P", self.msf_pass,
                    "-a", self.msf_host,
                    "-p", str(self.msf_port),
                    "-S"  # Start HTTPS
                ]
            else:
                # Normal execution
                cmd = [
                    msfrpcd_path,
                    "-U", self.msf_user,
                    "-P", self.msf_pass,
                    "-a", self.msf_host,
                    "-p", str(self.msf_port),
                    "-S"  # Start HTTPS
                ]
                
            # Redirect output to avoid blocking
            with open(os.devnull, "w") as devnull:
                self.msfrpcd_process = subprocess.Popen(
                    cmd,
                    stdout=devnull,
                    stderr=devnull,
                    start_new_session=True
                )
                
            # Wait for the service to start
            max_tries = 10
            for i in range(max_tries):
                time.sleep(1)
                if self.is_running():
                    self.logger.info(f"msfrpcd started successfully after {i+1} seconds")
                    return True
                    
            self.logger.error(f"Timed out waiting for msfrpcd to start after {max_tries} seconds")
            return False
        except Exception as e:
            self.logger.error(f"Error starting msfrpcd: {e}")
            return False
    
    def stop_msfrpcd(self):
        """Stop the msfrpcd service."""
        if not self.is_running():
            self.logger.info("msfrpcd is not running")
            return True
            
        try:
            if self.msfrpcd_process and self.msfrpcd_process.poll() is None:
                # If we started the process, terminate it
                self.logger.info("Terminating msfrpcd process")
                self.msfrpcd_process.terminate()
                self.msfrpcd_process.wait(timeout=5)
                return True
            else:
                # If it was started elsewhere, try to find and kill the process
                self.logger.info("Finding and stopping msfrpcd process")
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        if 'msfrpcd' in proc.info['name'] or any('msfrpcd' in cmd for cmd in proc.info['cmdline'] if cmd):
                            self.logger.info(f"Killing msfrpcd process with PID {proc.info['pid']}")
                            psutil.Process(proc.info['pid']).terminate()
                            return True
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                        
                # If we couldn't find it, try generic port killing
                try:
                    if platform.system() == "Linux":
                        # Find process using the port
                        result = subprocess.run(
                            ["fuser", f"{self.msf_port}/tcp"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                        if result.returncode == 0:
                            pid = result.stdout.strip()
                            self.logger.info(f"Killing process with PID {pid} using port {self.msf_port}")
                            subprocess.run(["kill", pid])
                            return True
                except Exception as e:
                    self.logger.warning(f"Error using fuser to kill msfrpcd: {e}")
                    
                self.logger.warning("Could not find msfrpcd process to kill")
                return False
        except Exception as e:
            self.logger.error(f"Error stopping msfrpcd: {e}")
            return False
    
    def generate_resource_script(self, commands):
        """Generate a Metasploit resource script with the given commands."""
        try:
            # Create a temporary resource script
            fd, path = tempfile.mkstemp(suffix='.rc', prefix='msf_')
            with os.fdopen(fd, 'w') as f:
                for cmd in commands:
                    f.write(f"{cmd}\n")
            return path
        except Exception as e:
            self.logger.error(f"Error generating resource script: {e}")
            return None
    
    def run_commands(self, commands, wait=True):
        """Run commands in Metasploit console."""
        try:
            # Create resource script
            script_path = self.generate_resource_script(commands)
            if not script_path:
                return False
                
            # Run msfconsole with the resource script
            cmd = ["msfconsole", "-q", "-r", script_path]
            
            if wait:
                # Run and wait for completion
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Clean up
                os.unlink(script_path)
                
                if result.returncode != 0:
                    self.logger.error(f"Error running msfconsole: {result.stderr}")
                    return False
                    
                return result.stdout
            else:
                # Run in background
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Clean up script later
                def cleanup_process():
                    try:
                        process.wait(timeout=1)
                        os.unlink(script_path)
                    except:
                        pass
                        
                # Start cleanup in a separate thread
                import threading
                threading.Thread(target=cleanup_process).start()
                
                return process
                
        except Exception as e:
            self.logger.error(f"Error running Metasploit commands: {e}")
            return False
            
    def find_exploits(self, service_name, port=None, os_type=None):
        """Find exploits for a given service."""
        try:
            commands = [
                f"search {service_name}" + (f" port:{port}" if port else "") + (f" platform:{os_type}" if os_type else ""),
                "exit"
            ]
            
            output = self.run_commands(commands)
            if not output:
                return []
                
            # Parse the output to extract exploits
            exploits = []
            for line in output.split('\n'):
                if 'exploit/' in line or 'auxiliary/' in line:
                    parts = re.split(r'\s{2,}', line.strip())
                    if len(parts) >= 3:
                        exploit_path = parts[0].strip()
                        exploit_name = parts[1].strip()
                        exploit_disclosure = parts[2].strip() if len(parts) > 2 else "Unknown"
                        
                        exploits.append({
                            'path': exploit_path,
                            'name': exploit_name,
                            'disclosure_date': exploit_disclosure,
                            'description': ' '.join(parts[3:]) if len(parts) > 3 else ""
                        })
                        
            return exploits
        except Exception as e:
            self.logger.error(f"Error finding exploits: {e}")
            return []
            
    def run_exploit(self, exploit_path, target_host, target_port, payload=None, options=None):
        """Run a Metasploit exploit against a target."""
        try:
            commands = [
                f"use {exploit_path}",
                f"set RHOSTS {target_host}",
                f"set RPORT {target_port}"
            ]
            
            if payload:
                commands.append(f"set PAYLOAD {payload}")
                
            if options:
                for option, value in options.items():
                    commands.append(f"set {option} {value}")
                    
            commands.append("exploit -j")
            commands.append("sessions -l")
            commands.append("exit")
            
            output = self.run_commands(commands)
            
            # Check if exploit was successful
            if "opened" in output.lower() or "session" in output.lower():
                self.logger.info(f"Exploit {exploit_path} successful against {target_host}:{target_port}")
                return True, output
            else:
                self.logger.warning(f"Exploit {exploit_path} failed against {target_host}:{target_port}")
                return False, output
                
        except Exception as e:
            self.logger.error(f"Error running exploit: {e}")
            return False, str(e) 