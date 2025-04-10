#!/usr/bin/env python3
"""
AI_MAL: AI-powered network scanner and vulnerability assessment tool
"""

import sys
import os
import argparse
import logging
from pathlib import Path
from datetime import datetime

def parse_arguments():
    """Parse command-line arguments according to use_cases.md."""
    parser = argparse.ArgumentParser(
        description="AI_MAL: AI-powered network scanner and vulnerability assessment tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Required arguments
    parser.add_argument("target", help="Target IP address or network range")
    
    # Scan type options
    parser.add_argument("--scan-type", choices=["quick", "full", "stealth"], default="quick",
                      help="Type of scan to perform")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode for minimal detection")
    parser.add_argument("--continuous", action="store_true", help="Run continuous scanning")
    parser.add_argument("--delay", type=int, default=300, help="Delay between scans in seconds")
    
    # Service detection options
    parser.add_argument("--services", action="store_true", help="Enable service detection")
    parser.add_argument("--version", action="store_true", help="Enable version detection")
    parser.add_argument("--os", action="store_true", help="Enable OS detection")
    
    # Vulnerability scanning options
    parser.add_argument("--vuln", action="store_true", help="Enable vulnerability scanning (OpenVAS when available, fallback to Nmap)")
    parser.add_argument("--openvas", action="store_true", help="Force OpenVAS for vulnerability scanning")
    parser.add_argument("--scan-config", choices=["full_and_fast", "full_and_very_deep", "discovery", 
                                        "system_discovery", "host_discovery"],
                      default="full_and_fast", help="OpenVAS scan configuration type")
    parser.add_argument("--use-nmap", action="store_true", help="Force Nmap for vulnerability scanning instead of OpenVAS")
    parser.add_argument("--dos", action="store_true", help="Enable DoS testing")
    
    # Feature flags
    parser.add_argument("--msf", action="store_true", help="Enable Metasploit integration")
    parser.add_argument("--exploit", action="store_true", help="Attempt exploitation of vulnerabilities")
    parser.add_argument("--custom-scripts", action="store_true", help="Enable AI-powered script generation")
    
    # Script options
    parser.add_argument("--script-type", choices=["python", "bash", "ruby"], default="python",
                      help="Script language for generated scripts")
    parser.add_argument("--execute-scripts", action="store_true", 
                      help="Automatically execute generated scripts")
    parser.add_argument("--script-output", default="/opt/AI_MAL/scripts",
                      help="Output directory for generated scripts")
    parser.add_argument("--script-format", choices=["raw", "base64"], default="raw",
                      help="Script format")
    
    # AI options
    parser.add_argument("--ai-analysis", action="store_true", help="Enable AI analysis of results")
    parser.add_argument("--model", default="artifish/llama3.2-uncensored", 
                      help="Primary AI model")
    parser.add_argument("--fallback-model", default="qwen2.5-coder:7b",
                      help="Fallback AI model")
    
    # Data operations
    parser.add_argument("--exfil", action="store_true", help="Enable data exfiltration")
    parser.add_argument("--implant", help="Path to implant script")
    
    # Output options
    parser.add_argument("--output-dir", default="/opt/AI_MAL/results", 
                      help="Output directory for results")
    parser.add_argument("--output-format", choices=["xml", "json"], default="json",
                      help="Output format")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    parser.add_argument("--no-gui", action="store_true", help="Disable terminal GUI features")
    
    # Logging options
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--log-level", choices=["debug", "info", "warning", "error"], 
                      default="info", help="Logging level")
    parser.add_argument("--log-dir", default="/opt/AI_MAL/logs", help="Directory for log files")
    parser.add_argument("--log-file", help="Specific log file path")
    
    # Custom vulnerability definitions
    parser.add_argument("--custom-vuln", help="Path to custom vulnerability definitions")
    
    return parser.parse_args()

def setup_logging(args):
    """Set up logging configuration based on arguments."""
    # Set log level based on args
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    
    # Create log directory if it doesn't exist
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Determine log file path
    if args.log_file:
        log_file = args.log_file
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"scan_{timestamp}.log"
    
    # Configure logging
    handlers = []
    
    # File handler
    handlers.append(logging.FileHandler(log_file))
    
    # Console handler (unless quiet mode is enabled)
    if not args.quiet:
        handlers.append(logging.StreamHandler(sys.stdout))
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers
    )
    
    return logging.getLogger("AI_MAL")

def main():
    """Main function for the scanner module."""
    # Parse arguments
    args = parse_arguments()
    
    # Set up logging
    logger = setup_logging(args)
    
    # Create output directory if it doesn't exist
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    
    # Log scan start
    logger.info(f"Starting scan of {args.target}")
    
    # Handle scan type settings
    if args.stealth:
        logger.info("Stealth mode enabled")
        args.scan_type = "stealth"
    
    logger.info(f"Scan type: {args.scan_type}")
    
    if args.continuous:
        logger.info(f"Continuous scanning enabled with {args.delay}s delay")
    
    # Log enabled features
    enabled_features = []
    
    # Service detection features
    if args.services:
        enabled_features.append("Service detection")
    if args.version:
        enabled_features.append("Version detection")
    if args.os:
        enabled_features.append("OS detection")
    
    # Advanced features
    if args.vuln or args.openvas:
        if args.openvas or (args.vuln and not args.use_nmap):
            enabled_features.append(f"OpenVAS vulnerability scanning ({args.scan_config})")
        else:
            enabled_features.append("Nmap vulnerability scanning")
    if args.dos:
        enabled_features.append("DoS testing")
    if args.msf:
        enabled_features.append("Metasploit integration")
    if args.exploit:
        enabled_features.append("Exploitation")
    if args.custom_scripts:
        enabled_features.append(f"Custom script generation ({args.script_type})")
    
    # AI features
    if args.ai_analysis:
        enabled_features.append(f"AI analysis (Model: {args.model})")
    
    # Data operation features
    if args.exfil:
        enabled_features.append("Data exfiltration")
    if args.implant:
        enabled_features.append(f"Implant deployment ({args.implant})")
    
    # Log enabled features
    if enabled_features:
        logger.info(f"Enabled features: {', '.join(enabled_features)}")
    
    try:
        # Import here to avoid circular imports
        from AI_MAL.main import AI_MAL
        
        # Configure scan parameters
        scan_params = {
            "target": args.target,
            "verbose": args.debug,
            "ai_analysis": args.ai_analysis,
            "generate_exploits": args.exploit,
            "run_msf": args.msf,
            "quiet": args.quiet,
            "output_dir": args.output_dir,
            "log_dir": args.log_dir,
            "model": args.model,
            "fallback_model": args.fallback_model,
            "exfil": args.exfil,
            "implant": args.implant,
            "services": args.services,
            "version": args.version,
            "os": args.os,
            "no_gui": args.no_gui,
            "scan_config": args.scan_config,
            "fallback_to_nmap": not args.use_nmap
        }
        
        # Determine scan type
        if args.openvas:
            scan_type = "openvas"
        elif args.scan_type == "stealth" or args.stealth:
            scan_type = "stealth"
        elif args.scan_type == "full":
            scan_type = "aggressive"
        elif args.vuln and not args.use_nmap:
            # Check if OpenVAS is available
            import asyncio
            from AI_MAL.core.openvas_manager import OpenVASManager
            
            try:
                openvas = OpenVASManager()
                status = asyncio.run(openvas.check_openvas_status())
                if status["installed"] and status["openvas_running"]:
                    logger.info("OpenVAS is available - using OpenVAS for vulnerability scanning")
                    scan_type = "openvas"
                else:
                    logger.warning("OpenVAS is not available - falling back to Nmap for vulnerability scanning")
                    scan_type = "quick" if args.scan_type == "quick" else "aggressive"
            except Exception as e:
                logger.warning(f"Failed to check OpenVAS status ({str(e)}) - falling back to Nmap for vulnerability scanning")
                scan_type = "quick" if args.scan_type == "quick" else "aggressive"
        else:
            scan_type = args.scan_type
        
        # Initialize AI_MAL scanner
        scanner = AI_MAL()
        
        # Enable vulnerability scanning if requested
        if args.vuln:
            scan_params["vuln_detection"] = True
        
        # Execute scan
        logger.info(f"Starting {scan_type} scan against {args.target}")
        results = scanner.run(target=args.target, scan_type=scan_type, **scan_params)
        
        # Check for errors
        if "error" in results:
            logger.error(f"Scan failed: {results['error']}")
            return 1
            
        logger.info("Scan completed successfully")
        
        # If continuous scanning is enabled, wait and repeat
        if args.continuous:
            import time
            
            while True:
                logger.info(f"Waiting {args.delay} seconds before next scan...")
                time.sleep(args.delay)
                
                logger.info(f"Starting next scan of {args.target}")
                results = scanner.run(target=args.target, scan_type=scan_type, **scan_params)
                
                # Check for errors
                if "error" in results:
                    logger.error(f"Scan failed: {results['error']}")
                    return 1
                    
                logger.info("Scan completed successfully")
        
        return 0
        
    except ImportError:
        logger.error("Failed to import AI_MAL module. Make sure it's installed correctly.")
        return 1
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        if args.debug:
            logger.exception("Detailed traceback:")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 