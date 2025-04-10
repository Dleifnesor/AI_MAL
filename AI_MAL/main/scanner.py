#!/usr/bin/env python3
"""
AI_MAL Scanner Module - Core scanning functionality
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
import os

from AI_MAL.core.adaptive import AdaptiveScanner
from AI_MAL.core.ai_manager import AIManager
from AI_MAL.core.metasploit import MetasploitManager
from AI_MAL.core.script_generator import ScriptGenerator
from AI_MAL.core.network_scanner import NetworkScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='AI_MAL - AI-Powered Penetration Testing Framework')
    
    # Required arguments
    parser.add_argument('target', help='Target IP address or network range')
    
    # Scan type options
    parser.add_argument('--scan-type', choices=['quick', 'full', 'stealth'],
                       default='quick', help='Type of scan to perform')
    parser.add_argument('--stealth', action='store_true',
                       help='Enable stealth mode for minimal detection')
    parser.add_argument('--continuous', action='store_true',
                       help='Run continuous scanning')
    parser.add_argument('--delay', type=int, default=300,
                       help='Delay between scans in seconds')
    
    # Feature flags
    parser.add_argument('--services', action='store_true',
                       help='Enable service detection')
    parser.add_argument('--version', action='store_true',
                       help='Enable version detection')
    parser.add_argument('--os', action='store_true',
                       help='Enable OS detection')
    parser.add_argument('--vuln', action='store_true',
                       help='Enable vulnerability scanning')
    parser.add_argument('--dos', action='store_true',
                       help='Enable DoS testing')
    parser.add_argument('--msf', action='store_true',
                       help='Enable Metasploit integration')
    parser.add_argument('--exploit', action='store_true',
                       help='Attempt exploitation of vulnerabilities')
    parser.add_argument('--custom-scripts', action='store_true',
                       help='Enable AI-powered script generation')
    
    # Script options
    parser.add_argument('--script-type', choices=['python', 'bash', 'ruby'],
                       default='python', help='Script language')
    parser.add_argument('--execute-scripts', action='store_true',
                       help='Automatically execute generated scripts')
    parser.add_argument('--script-output', type=str, default='./scripts',
                       help='Output directory for generated scripts')
    parser.add_argument('--script-format', choices=['raw', 'base64'],
                       default='raw', help='Script format')
    
    # AI options
    parser.add_argument('--ai-analysis', action='store_true',
                       help='Enable AI analysis of results')
    parser.add_argument('--model', type=str,
                       default='artifish/llama3.2-uncensored',
                       help='Primary AI model')
    parser.add_argument('--fallback-model', type=str,
                       default='gemma3:1b',
                       help='Fallback AI model')
    
    # Advanced features
    parser.add_argument('--exfil', action='store_true',
                       help='Enable data exfiltration')
    parser.add_argument('--implant', type=str,
                       help='Path to implant script')
    
    # Output options
    parser.add_argument('--output-dir', type=str, default='./results',
                       help='Output directory for results')
    parser.add_argument('--output-format', choices=['xml', 'json'],
                       default='json', help='Output format')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress progress output')
    parser.add_argument('--no-gui', action='store_true',
                       help='Disable terminal GUI features')
    
    # Logging options
    parser.add_argument('--log-level', choices=['debug', 'info', 'warning', 'error'],
                       default='info', help='Logging level')
    parser.add_argument('--log-file', type=str, default='logs/AI_MAL.log',
                       help='Log file path')
    
    # Automation options
    parser.add_argument('--full-auto', action='store_true',
                       help='Enable full automation mode')
    parser.add_argument('--custom-vuln', type=str,
                       help='Path to custom vulnerability definitions')
    
    return parser.parse_args()

def main() -> None:
    """Main function for the scanner module."""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Set logging level
        logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
        
        # Initialize components
        scanner = NetworkScanner()
        ai_manager = AIManager()
        script_generator = ScriptGenerator()
        msf_manager = MetasploitManager()
        
        # Configure scan based on arguments
        scan_config = {
            'target': args.target,
            'scan_type': args.scan_type,
            'stealth': args.stealth,
            'continuous': args.continuous,
            'delay': args.delay,
            'services': args.services,
            'version': args.version,
            'os': args.os,
            'vulnerability_scan': args.vuln,
            'dos': args.dos,
            'custom_scripts': args.custom_scripts,
            'script_type': args.script_type,
            'execute_scripts': args.execute_scripts,
            'script_output': args.script_output,
            'script_format': args.script_format,
            'ai_analysis': args.ai_analysis,
            'model': args.model,
            'fallback_model': args.fallback_model,
            'exfil': args.exfil,
            'implant': args.implant,
            'output_dir': args.output_dir,
            'output_format': args.output_format,
            'quiet': args.quiet,
            'no_gui': args.no_gui,
            'custom_vuln': args.custom_vuln
        }
        
        # Perform scan
        logger.info(f"Starting {args.scan_type} scan on {args.target}")
        scan_results = scanner.scan(**scan_config)
        
        if not scan_results:
            logger.error("Scan failed to produce results")
            sys.exit(1)
        
        # Process results based on enabled features
        if args.ai_analysis:
            logger.info("Performing AI analysis")
            analysis = ai_manager.analyze_results(scan_results)
            if analysis:
                logger.info("AI analysis completed")
        
        if args.custom_scripts:
            logger.info("Generating exploit scripts")
            scripts = script_generator.generate_scripts(scan_results)
            if scripts:
                logger.info(f"Generated {len(scripts)} exploit scripts")
        
        if args.msf:
            logger.info("Running Metasploit modules")
            msf_results = msf_manager.execute_exploits(scan_results)
            if msf_results:
                logger.info("Metasploit execution completed")
        
        logger.info("Scan completed successfully")
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 