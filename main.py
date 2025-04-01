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