#!/usr/bin/env python3
"""AI_MAL - AI-Powered Penetration Testing Tool"""

import argparse
import logging
import os
import sys
import time
import asyncio
import json
from typing import Optional
import subprocess
from pathlib import Path

from .core.adaptive import AdaptiveNmapScanner, ScanConfig
from .core.network_discovery import NetworkDiscovery
from .core.vulnerability_scanner import VulnerabilityScanner
from .core.ai_manager import AIManager
from .core.metasploit_manager import MetasploitManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ai_mal.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def check_kali_environment():
    """Check if running in Kali Linux environment."""
    try:
        # Check for Kali Linux specific files
        if not Path("/etc/os-release").exists():
            logger.warning("Not running in Kali Linux environment")
            return False
            
        with open("/etc/os-release", "r") as f:
            if "Kali GNU/Linux" not in f.read():
                logger.warning("Not running in Kali Linux environment")
                return False
                
        # Check for required tools
        required_tools = ["nmap", "msfconsole", "msfvenom"]
        for tool in required_tools:
            if not subprocess.run(["which", tool], capture_output=True).returncode == 0:
                logger.error(f"Required tool {tool} not found")
                return False
                
        return True
    except Exception as e:
        logger.error(f"Error checking Kali environment: {e}")
        return False

async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="AI_MAL - AI-Powered Penetration Testing Tool")
    parser.add_argument("target", help="Target IP address or range")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-p", "--ports", default="all", help="Port range to scan (all, quick, or custom range)")
    parser.add_argument("-t", "--scan-type", choices=["quick", "full", "stealth"], default="quick",
                      help="Type of scan to perform")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("--continuous", action="store_true", help="Run continuous scanning")
    parser.add_argument("--delay", type=int, default=300, help="Delay between scans in seconds")
    parser.add_argument("-o", "--output-dir", default="scan_results", help="Output directory")
    parser.add_argument("--vuln-db", help="Path to custom vulnerability database")
    parser.add_argument("--workspace", default="ai_mal_workspace", help="Metasploit workspace name")
    parser.add_argument("--auto-discover", action="store_true", help="Auto-discover hosts on network")
    parser.add_argument("--network", help="Target network in CIDR notation")
    parser.add_argument("--scan-all", action="store_true", help="Scan all discovered hosts")
    parser.add_argument("--services", action="store_true", help="Enable service detection")
    parser.add_argument("--version", action="store_true", help="Enable version detection")
    parser.add_argument("--os", action="store_true", help="Enable OS detection")
    parser.add_argument("--vuln", action="store_true", help="Enable vulnerability scanning")
    parser.add_argument("--exploit", action="store_true", help="Attempt exploitation of vulnerabilities")
    parser.add_argument("--custom", help="Path to custom vulnerability definitions")
    parser.add_argument("--output-format", choices=["xml", "json"], default="xml",
                      help="Output format for scan results")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    parser.add_argument("--iterations", type=int, default=1, help="Number of scan iterations")
    parser.add_argument("--generate-script", action="store_true", help="Generate attack script")
    parser.add_argument("--model", help="Ollama model to use (default: qwen2.5-coder:7b)")
    parser.add_argument("--ai-analysis", action="store_true", help="Enable AI analysis of results")
    parser.add_argument("--no-fallback", action="store_true", help="Disable fallback model")
    parser.add_argument("--msf", action="store_true", help="Enable Metasploit integration")
    parser.add_argument("--full-auto", action="store_true", help="Enable full automation mode")
    parser.add_argument("--dos", action="store_true", help="Attempt Denial of Service attacks")
    parser.add_argument("--custom-scripts", action="store_true", help="Enable AI-powered script generation")
    parser.add_argument("--script-type", choices=["bash", "python", "ruby"], default="python",
                      help="Type of script to generate")
    parser.add_argument("--execute-scripts", action="store_true", help="Automatically execute generated scripts")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout for model responses")
    parser.add_argument("--max-threads", type=int, default=4, help="Limit concurrent scan operations")
    parser.add_argument("--memory-limit", help="Set memory limit for operations")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--log", help="Log file path")
    
    args = parser.parse_args()
    
    # Check Kali environment
    if not check_kali_environment():
        logger.warning("Some features may not work properly outside Kali Linux")
    
    # Set up logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.log:
        file_handler = logging.FileHandler(args.log)
        logging.getLogger().addHandler(file_handler)
    
    # Create scan configuration
    config = ScanConfig(
        target=args.target,
        interface=args.interface,
        ports=args.ports,
        scan_type=args.scan_type,
        stealth=args.stealth,
        continuous=args.continuous,
        delay=args.delay,
        output_dir=args.output_dir,
        vuln_db_path=args.vuln_db,
        workspace=args.workspace,
        auto_discover=args.auto_discover,
        network=args.network,
        scan_all=args.scan_all,
        services=args.services,
        version_detection=args.version,
        os_detection=args.os,
        vulnerability_scan=args.vuln,
        custom_vuln_file=args.custom,
        output_format=args.output_format,
        quiet=args.quiet,
        iterations=args.iterations,
        generate_script=args.generate_script
    )
    
    # Initialize AI manager if needed
    ai_manager = None
    if args.ai_analysis or args.generate_script or args.custom_scripts:
        ai_manager = AIManager(model_name=args.model)
        if args.no_fallback:
            ai_manager.fallback_model = None
    
    # Initialize Metasploit manager if needed
    msf_manager = None
    if args.msf or args.exploit or args.full_auto:
        msf_manager = MetasploitManager(config.workspace)
    
    # Create and run scanner
    scanner = AdaptiveNmapScanner(config)
    scan_results = await scanner.run()
    
    # Perform AI analysis if enabled
    if args.ai_analysis and ai_manager:
        logger.info("Performing AI analysis of scan results...")
        analysis = await ai_manager.analyze_scan_results(scan_results)
        logger.info("AI Analysis Results:")
        logger.info(f"Risk Level: {analysis['risk_level']}")
        logger.info(f"Summary: {analysis['summary']}")
        logger.info(f"Vulnerabilities Found: {len(analysis['vulnerabilities'])}")
        logger.info(f"Attack Vectors: {len(analysis['attack_vectors'])}")
        logger.info(f"Recommendations: {len(analysis['recommendations'])}")
        
        # Save analysis results
        output_file = os.path.join(args.output_dir, "ai_analysis.json")
        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        logger.info(f"Analysis results saved to {output_file}")
    
    # Handle Metasploit integration
    if args.msf or args.exploit or args.full_auto:
        if not msf_manager:
            logger.error("Metasploit manager not initialized")
            return
            
        # Generate and execute Metasploit resource scripts
        if args.full_auto:
            logger.info("Generating and executing Metasploit resource scripts...")
            await msf_manager.generate_and_execute_scripts(scan_results, analysis if args.ai_analysis else None)
        elif args.exploit:
            logger.info("Attempting exploitation...")
            await msf_manager.run_exploits(scan_results)
        else:
            logger.info("Setting up Metasploit workspace...")
            await msf_manager.setup_workspace(scan_results)
    
    # Generate and execute custom scripts if requested
    if args.custom_scripts and ai_manager:
        logger.info("Generating custom scripts...")
        scripts = await ai_manager.generate_custom_scripts(scan_results, args.script_type)
        
        if args.execute_scripts:
            logger.info("Executing generated scripts...")
            for script_path, script_content in scripts.items():
                try:
                    with open(script_path, 'w') as f:
                        f.write(script_content)
                    os.chmod(script_path, 0o755)
                    subprocess.run([script_path], check=True)
                except Exception as e:
                    logger.error(f"Error executing script {script_path}: {e}")
    
    # Generate attack script if requested
    if args.generate_script and ai_manager:
        logger.info("Generating attack script...")
        script = await ai_manager.generate_attack_script(scan_results)
        script_file = os.path.join(args.output_dir, "attack_script.py")
        with open(script_file, 'w') as f:
            f.write(script)
        logger.info(f"Attack script saved to {script_file}")
        
        if args.execute_scripts:
            logger.info("Executing attack script...")
            try:
                os.chmod(script_file, 0o755)
                subprocess.run([script_file], check=True)
            except Exception as e:
                logger.error(f"Error executing attack script: {e}")

if __name__ == "__main__":
    asyncio.run(main()) 