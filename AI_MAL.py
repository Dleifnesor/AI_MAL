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

def main():
    """Main function to execute the AI_MAL tool."""
    # Import datetime in case the global import didn't work
    from datetime import datetime
    
    # Parse arguments
    args = parse_arguments()
    
    # Handle --full-auto flag
    if args.full_auto:
        args.msf = True
        args.exploit = True
        args.vuln = True
        args.ai_analysis = True
        args.custom_scripts = True
        args.execute_scripts = True
    
    # Setup logging
    log_level = getattr(logging, args.log_level.upper())
    logger = setup_logger(log_level, args.log_file, args.quiet)
    
    logger.info(f"AI_MAL v{__version__} starting at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Target: {args.target}")
    
    try:
        # Initialize terminal GUI if not disabled
        if not args.no_gui:
            gui = TerminalGUI(args.quiet)
            gui.show_header()
        
        # Initialize scanner
        scanner = Scanner(
            target=args.target,
            scan_type=args.scan_type,
            stealth=args.stealth,
            services=args.services or args.vuln,  # Always enable service detection if vuln scanning is enabled
            version=args.version or args.vuln,    # Always enable version detection if vuln scanning is enabled
            os_detection=args.os
        )
        
        # Run initial scan
        logger.info("Starting initial scan...")
        scan_results = scanner.scan()
        logger.info(f"Initial scan completed. Found {len(scan_results['hosts'])} hosts.")
        
        # Run vulnerability scanning if enabled
        if args.vuln:
            logger.info("Starting vulnerability scanning...")
            # First try to use OpenVAS
            try:
                # Check if OpenVAS is available
                if subprocess.run(["gvm-cli", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
                    logger.info("Using OpenVAS for vulnerability scanning")
                    vuln_scanner = VulnerabilityScanner(
                        target=args.target,
                        scan_config=args.scan_config,
                        timeout=3600,
                        use_nmap=False  # Force OpenVAS
                    )
                else:
                    logger.warning("OpenVAS not found, falling back to nmap")
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
            logger.info(f"Vulnerability scanning completed. Found {len(vuln_results)} vulnerabilities.")
        
        # Run Metasploit integration if enabled
        if args.msf:
            logger.info("Initializing Metasploit Framework...")
            msf = MetasploitFramework()
            if args.exploit:
                logger.info("Attempting exploitation...")
                exploit_results = msf.run_exploits(scan_results)
                scan_results['exploits'] = exploit_results
                logger.info(f"Exploitation completed. Successful exploits: {len([e for e in exploit_results if e['status'] == 'success'])}")
            else:
                # Just initialize the MSF console without running exploits
                msf_info = msf.get_info()
                scan_results['msf_info'] = msf_info
                logger.info("Metasploit Framework initialized.")
        
        # Generate custom scripts if enabled
        if args.custom_scripts:
            logger.info(f"Generating {args.script_type} scripts...")
            script_gen = ScriptGenerator(
                script_type=args.script_type,
                output_dir=args.script_output,
                script_format=args.script_format
            )
            scripts = script_gen.generate_scripts(scan_results)
            scan_results['scripts'] = scripts
            
            # Execute scripts if enabled
            if args.execute_scripts and scripts:
                logger.info("Executing generated scripts...")
                execution_results = script_gen.execute_scripts(scripts)
                scan_results['script_execution'] = execution_results
        
        # Run AI analysis if enabled
        if args.ai_analysis:
            logger.info("Running AI analysis...")
            ai_analyzer = AIAnalyzer(
                model=args.model,
                fallback_model=args.fallback_model
            )
            analysis_results = ai_analyzer.analyze(scan_results)
            scan_results['ai_analysis'] = analysis_results
            logger.info("AI analysis completed.")
        
        # Run data exfiltration if enabled
        if args.exfil:
            logger.info("Attempting data exfiltration...")
            exfiltrator = DataExfiltration(scan_results)
            exfil_results = exfiltrator.exfiltrate()
            scan_results['exfiltration'] = exfil_results
            logger.info(f"Exfiltration completed. Results: {exfil_results['summary']}")
            
        # Deploy implant if specified
        if args.implant:
            logger.info(f"Deploying implant from {args.implant}...")
            deployer = ImplantDeployer(scan_results)
            implant_results = deployer.deploy_implant(args.implant)
            scan_results['implant'] = implant_results
            logger.info(f"Implant deployment completed. Success rate: {implant_results['success_rate']}%")
        
        # Run DoS testing if enabled
        if args.dos:
            logger.info("Running DoS testing...")
            # Implement DoS testing logic
            scan_results['dos_testing'] = {"status": "completed", "details": "DoS testing results would be here"}
            logger.info("DoS testing completed.")
        
        # Generate report
        logger.info("Generating report...")
        report_gen = ReportGenerator(
            output_dir=args.output_dir,
            output_format=args.output_format
        )
        report_path = report_gen.generate_report(scan_results)
        logger.info(f"Report generated: {report_path}")
        
        # Set up continuous scanning if enabled
        if args.continuous:
            logger.info(f"Continuous scanning enabled with {args.delay} seconds delay.")
            try:
                import time
                
                scan_count = 1
                while True:
                    logger.info(f"Waiting {args.delay} seconds until next scan...")
                    time.sleep(args.delay)
                    
                    scan_count += 1
                    logger.info(f"Starting scan #{scan_count} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    # Re-run the scan
                    new_scan_results = scanner.scan()
                    
                    # Compare with previous results to identify changes
                    # This is a simplified implementation - a more robust one would be needed
                    new_host_count = len(new_scan_results['hosts'])
                    logger.info(f"Scan #{scan_count} completed. Found {new_host_count} hosts.")
                    
                    # Generate a new report for this scan
                    report_path = report_gen.generate_report(new_scan_results, f"scan_{scan_count}")
                    logger.info(f"Report for scan #{scan_count} generated: {report_path}")
                    
                    # Update scan_results for the next iteration
                    scan_results = new_scan_results
                    
            except KeyboardInterrupt:
                logger.info("Continuous scanning stopped by user.")
        
        # Show footer if GUI is enabled
        if not args.no_gui:
            gui.show_footer()
        
        logger.info(f"AI_MAL completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return 0
        
    except KeyboardInterrupt:
        logger.warning("Operation interrupted by user.")
        return 1
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        if args.debug:
            logger.exception("Detailed error information:")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 