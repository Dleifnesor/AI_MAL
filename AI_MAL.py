#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL - AI-Powered Penetration Testing Tool
============================================

An advanced penetration testing tool that combines traditional scanning techniques 
with AI-powered analysis and automation.
"""

import os
import sys
import argparse
import logging
from datetime import datetime
import subprocess
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.syntax import Syntax
from rich.markdown import Markdown
import gvm
from gvm.connections import TLSConnection
from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print

# Import core modules
from src.core.logger import setup_logger
from src.core.scanner import Scanner
from src.core.ai_analysis import AIAnalyzer
from src.core.msf_integration import MetasploitFramework
from src.core.vuln_scanner import VulnerabilityScanner
from src.core.script_generator import ScriptGenerator
from src.core.terminal_gui import TerminalGUI
from src.core.report_generator import ReportGenerator
from src.core.exfiltration import DataExfiltration  # Import the exfiltration module
from src.core.implant import ImplantDeployer  # Import the implant deployer module

__version__ = "1.0.0"

# Initialize rich console
console = Console()

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AI_MAL - AI-Powered Penetration Testing Tool",
        epilog="Example: AI_MAL 192.168.1.1 --scan-type full --vuln --msf --ai-analysis"
    )
    
    parser.add_argument("target", help="Target IP address, hostname, or network range")
    
    # Scan options
    parser.add_argument("--scan-type", default="quick", choices=["quick", "full", "stealth"],
                        help="Type of scan to perform (quick/full/stealth)")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode for minimal detection")
    parser.add_argument("--continuous", action="store_true", help="Run continuous scanning")
    parser.add_argument("--delay", type=int, default=300, help="Delay between scans in seconds")
    
    # Detection options
    parser.add_argument("--services", action="store_true", help="Enable service detection")
    parser.add_argument("--version", action="store_true", help="Enable version detection")
    parser.add_argument("--os", action="store_true", help="Enable OS detection")
    
    # Vulnerability scanning - Set OpenVAS as default
    parser.add_argument("--vuln", action="store_true", help="Enable vulnerability scanning (OpenVAS by default)")
    parser.add_argument("--openvas", action="store_true", help="Force OpenVAS for vulnerability scanning (no fallback)")
    parser.add_argument("--scan-config", default="full_and_fast", 
                        choices=["full_and_fast", "full_and_fast_ultimate", "full_and_very_deep", "empty", "discovery", "host_discovery"],
                        help="OpenVAS scan configuration type")
    parser.add_argument("--use-nmap", action="store_true", help="Force Nmap for vulnerability scanning")
    
    # Testing options
    parser.add_argument("--dos", action="store_true", help="Enable DoS testing")
    
    # Metasploit options
    parser.add_argument("--msf", action="store_true", help="Enable Metasploit integration")
    parser.add_argument("--exploit", action="store_true", help="Attempt exploitation of vulnerabilities")
    
    # Custom script options
    parser.add_argument("--custom-scripts", action="store_true", help="Enable AI-powered script generation")
    parser.add_argument("--script-type", default="python", choices=["python", "bash", "ruby"],
                        help="Script language (python/bash/ruby)")
    parser.add_argument("--execute-scripts", action="store_true", help="Automatically execute generated scripts")
    parser.add_argument("--script-output", default="./scripts", help="Output directory for generated scripts")
    parser.add_argument("--script-format", default="raw", choices=["raw", "base64"],
                        help="Script format (raw/base64)")
    
    # AI options
    parser.add_argument("--ai-analysis", action="store_true", default=True, help="Enable AI analysis of results")
    parser.add_argument("--model", default="artifish/llama3.2-uncensored", help="Primary AI model")
    parser.add_argument("--fallback-model", default="gemma3:1b", help="Fallback AI model")
    
    # Advanced options
    parser.add_argument("--exfil", action="store_true", help="Enable data exfiltration")
    parser.add_argument("--implant", help="Path to implant script")
    
    # Output options
    parser.add_argument("--output-dir", default="./results", help="Output directory for results")
    parser.add_argument("--output-format", default="json", choices=["xml", "json"],
                        help="Output format (xml/json)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    parser.add_argument("--no-gui", action="store_true", help="Disable terminal GUI features")
    
    # Debug options
    parser.add_argument("--debug", action="store_true", help="Enable debug mode with verbose output")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"],
                        help="Logging level (debug/info/warning/error)")
    parser.add_argument("--log-file", default="logs/AI_MAL.log", help="Log file path")
    
    # Automation options
    parser.add_argument("--full-auto", action="store_true", 
                        help="Enable full automation mode (equivalent to --msf --exploit --vuln --ai-analysis --custom-scripts --execute-scripts)")
    parser.add_argument("--custom-vuln", help="Path to custom vulnerability definitions")
    
    return parser.parse_args()

def display_scan_results(scan_results):
    """Display scan results in a rich format."""
    # Create a table for hosts
    hosts_table = Table(title="[bold cyan]Discovered Hosts[/bold cyan]")
    hosts_table.add_column("IP Address", style="cyan")
    hosts_table.add_column("Hostname", style="green")
    hosts_table.add_column("OS", style="yellow")
    hosts_table.add_column("Open Ports", style="magenta")
    
    for host in scan_results.get('hosts', []):
        hosts_table.add_row(
            host.get('ip', 'N/A'),
            host.get('hostname', 'N/A'),
            host.get('os', 'N/A'),
            ', '.join(str(p) for p in host.get('ports', []))
        )
    
    console.print(Panel(hosts_table, title="[bold]Network Scan Results[/bold]"))

def display_vulnerabilities(vuln_results):
    """Display vulnerability scan results in a rich format."""
    if not vuln_results:
        return
    
    vuln_table = Table(title="[bold red]Vulnerabilities Found[/bold red]")
    vuln_table.add_column("Host", style="cyan")
    vuln_table.add_column("Port", style="green")
    vuln_table.add_column("Service", style="yellow")
    vuln_table.add_column("Vulnerability", style="red")
    vuln_table.add_column("Severity", style="magenta")
    
    for vuln in vuln_results:
        vuln_table.add_row(
            vuln.get('host', 'N/A'),
            str(vuln.get('port', 'N/A')),
            vuln.get('service', 'N/A'),
            vuln.get('name', 'N/A'),
            vuln.get('severity', 'N/A')
        )
    
    console.print(Panel(vuln_table, title="[bold]Vulnerability Scan Results[/bold]"))

def display_ai_analysis(analysis_results):
    """Display AI analysis results in a rich format."""
    if not analysis_results:
        return
    
    # Create panels for different aspects of AI analysis
    console.print(Panel(
        Markdown(analysis_results.get('summary', 'No analysis available')),
        title="[bold green]AI Analysis Summary[/bold green]"
    ))
    
    if 'recommendations' in analysis_results:
        console.print(Panel(
            Markdown('\n'.join(f"- {rec}" for rec in analysis_results['recommendations'])),
            title="[bold yellow]Recommended Actions[/bold yellow]"
        ))
    
    if 'exploitation_paths' in analysis_results:
        console.print(Panel(
            Markdown('\n'.join(f"- {path}" for path in analysis_results['exploitation_paths'])),
            title="[bold red]Potential Exploitation Paths[/bold red]"
        ))

def connect_to_openvas():
    """Connect to OpenVAS/GVM and return the connection."""
    try:
        # Try to connect to OpenVAS on localhost:9392
        connection = TLSConnection(hostname='127.0.0.1', port=9392)
        transform = EtreeTransform()
        gmp = Gmp(connection, transform=transform)
        
        # Get credentials from environment variables
        username = os.getenv('GVM_USERNAME', 'admin')
        password = os.getenv('GVM_PASSWORD', 'admin')
        
        # Authenticate with credentials
        gmp.authenticate(username, password)
        console.print("[green]Successfully connected to OpenVAS[/green]")
        return gmp
    except Exception as e:
        console.print(f"[red]Failed to connect to OpenVAS: {e}[/red]")
        return None

def check_openvas_availability():
    """Check if OpenVAS is available and running."""
    try:
        # Check if gvm-cli is installed
        if not subprocess.run(["which", "gvm-cli"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
            console.print("[yellow]gvm-cli is not installed[/yellow]")
            return False
            
        # Check if OpenVAS service is running
        if not subprocess.run(["systemctl", "is-active", "--quiet", "gvmd"]).returncode == 0:
            console.print("[yellow]OpenVAS service (gvmd) is not running[/yellow]")
            return False
            
        # Try to connect to OpenVAS
        gmp = connect_to_openvas()
        if gmp:
            return True
            
        return False
    except Exception as e:
        console.print(f"[red]Error checking OpenVAS availability: {e}[/red]")
        return False

def main():
    """Main function to execute the AI_MAL tool."""
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    log_level = getattr(logging, args.log_level.upper())
    logger = setup_logger(log_level, args.log_file, args.quiet)
    
    console.print(Panel.fit(
        f"[bold cyan]AI_MAL v{__version__}[/bold cyan]\n"
        f"[yellow]Starting at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]\n"
        f"[green]Target: {args.target}[/green]",
        title="[bold]AI_MAL Penetration Testing Tool[/bold]"
    ))
    
    try:
        # Initialize scanner with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Initializing scanner...", total=None)
            
            scanner = Scanner(
                target=args.target,
                scan_type=args.scan_type,
                stealth=args.stealth,
                services=args.services or args.vuln,
                version=args.version or args.vuln,
                os_detection=args.os
            )
            
            # Run initial scan
            progress.update(task, description="[cyan]Running initial scan...")
            scan_results = scanner.scan()
            progress.update(task, description="[green]Initial scan completed!")
            
            # Display scan results
            display_scan_results(scan_results)
            
            # Run vulnerability scanning if enabled
            if args.vuln:
                logger.info("Starting vulnerability scanning...")
                progress.update(task, description="[cyan]Running vulnerability scan...")
                
                # First try to use OpenVAS
                try:
                    # Check if OpenVAS is available and running
                    openvas_available = check_openvas_availability()
                    
                    if openvas_available:
                        vuln_scanner = VulnerabilityScanner(
                            target=args.target,
                            scan_config=args.scan_config,
                            timeout=3600,
                            use_nmap=False,  # Force OpenVAS
                            gmp_connection=connect_to_openvas()  # Pass the GMP connection
                        )
                        logger.info("Using OpenVAS for vulnerability scanning")
                    else:
                        logger.warning("OpenVAS not available, falling back to nmap")
                        vuln_scanner = VulnerabilityScanner(
                            target=args.target,
                            scan_config=args.scan_config,
                            timeout=3600,
                            use_nmap=True
                        )
                except Exception as e:
                    logger.warning(f"Error checking OpenVAS: {e}, falling back to nmap")
                    vuln_scanner = VulnerabilityScanner(
                        target=args.target,
                        scan_config=args.scan_config,
                        timeout=3600,
                        use_nmap=True
                    )
                
                vuln_results = vuln_scanner.scan()
                scan_results['vulnerabilities'] = vuln_results
                progress.update(task, description="[green]Vulnerability scan completed!")
                
                # Display vulnerability results
                display_vulnerabilities(vuln_results)
            
            # Run AI analysis if enabled
            if args.ai_analysis:
                progress.update(task, description="[cyan]Running AI analysis...")
                ai_analyzer = AIAnalyzer(
                    model=args.model,
                    fallback_model=args.fallback_model
                )
                analysis_results = ai_analyzer.analyze(scan_results)
                scan_results['ai_analysis'] = analysis_results
                progress.update(task, description="[green]AI analysis completed!")
                
                # Display AI analysis results
                display_ai_analysis(analysis_results)
            
            # Generate report
            progress.update(task, description="[cyan]Generating report...")
            report_gen = ReportGenerator(
                output_dir=args.output_dir,
                output_format=args.output_format
            )
            report_path = report_gen.generate_report(scan_results)
            progress.update(task, description="[green]Report generated!")
            
            console.print(Panel(
                f"[bold green]Report saved to:[/bold green] {report_path}",
                title="[bold]Operation Complete[/bold]"
            ))
            
    except KeyboardInterrupt:
        console.print("[yellow]Operation interrupted by user.[/yellow]")
        return 1
    except Exception as e:
        console.print(f"[bold red]An error occurred:[/bold red] {str(e)}")
        if args.debug:
            console.print_exception()
        return 1

if __name__ == "__main__":
    sys.exit(main()) 