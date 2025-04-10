#!/usr/bin/env python3
"""
OpenVAS vulnerability scanning module for AI_MAL
"""

import os
import sys
import asyncio
import argparse
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ai_mal.openvas")

# Import OpenVAS Manager
try:
    from AI_MAL.core.openvas_manager import OpenVASManager
    from AI_MAL.core.ai_manager import AIManager
except ImportError:
    logger.error("Unable to import required modules. Make sure AI_MAL is installed correctly.")
    sys.exit(1)

async def run_scan(args) -> Dict[str, Any]:
    """
    Run an OpenVAS scan based on command-line arguments.
    
    Args:
        args: Command-line arguments
        
    Returns:
        Dictionary with scan results
    """
    # Configure output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Set up file handler for logging
    log_file = output_dir / f"openvas_scan_{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)
    
    # Set up verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
    
    # Initialize OpenVAS manager
    openvas_config = {
        "results_dir": str(output_dir),
        "gvm_user": args.username,
        "gvm_password": args.password
    }
    openvas = OpenVASManager(config=openvas_config)
    
    # Initialize AI manager if needed
    ai_manager = None
    if args.ai_analysis:
        ai_model = os.getenv('OLLAMA_MODEL', 'artifish/llama3.2-uncensored')
        fallback_model = os.getenv('OLLAMA_FALLBACK_MODEL', 'qwen2.5-coder:7b')
        ai_manager = AIManager(model=ai_model, fallback_model=fallback_model)
    
    # Check OpenVAS status
    logger.info("Checking OpenVAS status...")
    status = await openvas.check_openvas_status()
    
    if not status["installed"]:
        logger.error("OpenVAS is not installed. Please install OpenVAS first.")
        if args.fallback_to_nmap and not args.no_fallback:
            logger.info("Falling back to Nmap vulnerability scan")
            return run_nmap_scan(args)
        return {"error": "OpenVAS is not installed"}
    
    # Display OpenVAS status
    logger.info(f"OpenVAS version: {status.get('version', 'Unknown')}")
    logger.info(f"OpenVAS running: {status['openvas_running']}")
    logger.info(f"Redis running: {status['redis_running']}")
    logger.info(f"GVMD running: {status['gvmd_running']}")
    logger.info(f"GSAD running: {status['gsad_running']}")
    logger.info(f"OSPD-OpenVAS running: {status['ospd_openvas_running']}")
    
    # Start OpenVAS services if not running
    if not status["openvas_running"]:
        logger.info("Starting OpenVAS services...")
        if not await openvas.start_openvas_services():
            logger.error("Failed to start OpenVAS services. Check permissions and try again.")
            if args.fallback_to_nmap and not args.no_fallback:
                logger.info("Falling back to Nmap vulnerability scan")
                return run_nmap_scan(args)
            return {"error": "Failed to start OpenVAS services"}
    
    # Update feeds if requested
    if args.update_feeds:
        logger.info("Updating OpenVAS feeds. This may take a while...")
        if await openvas.update_feeds():
            logger.info("OpenVAS feeds updated successfully.")
        else:
            logger.warning("Failed to update OpenVAS feeds. Continuing with scan...")
    
    # Run the scan
    logger.info(f"Starting OpenVAS scan of target: {args.target}")
    scan_results = await openvas.scan(
        target=args.target,
        scan_name=args.scan_name,
        scan_config=args.scan_config
    )
    
    # Check for scan errors
    if "error" in scan_results:
        logger.error(f"Scan error: {scan_results['error']}")
        if args.fallback_to_nmap and not args.no_fallback:
            logger.info("Falling back to Nmap vulnerability scan")
            return run_nmap_scan(args)
        return {"error": scan_results["error"]}
    
    # Display scan summary
    vuln_count = len(scan_results.get('vulnerabilities', []))
    logger.info(f"Scan completed. Found {vuln_count} vulnerabilities.")
    
    # Save scan results as JSON
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    json_path = output_dir / f"openvas_scan_{timestamp}.json"
    try:
        with open(json_path, 'w') as f:
            json.dump(scan_results, f, indent=2)
        logger.info(f"Scan results saved to {json_path}")
    except Exception as e:
        logger.error(f"Failed to save scan results: {e}")
    
    # Perform AI analysis if requested
    if args.ai_analysis and ai_manager:
        logger.info("Performing AI analysis of scan results...")
        
        # Convert OpenVAS results to AI_MAL format
        ai_mal_scan_data = {
            "target": args.target,
            "scan_type": "vulnerability",
            "openvas_results": scan_results,
            "vulnerabilities": scan_results.get("vulnerabilities", []),
            "hosts": scan_results.get("hosts", [])
        }
        
        # Run AI analysis
        analysis = await ai_manager.analyze_results(ai_mal_scan_data)
        
        # Add analysis to results
        if analysis:
            scan_results["ai_analysis"] = analysis
            
            # Save analysis as JSON
            analysis_path = output_dir / f"ai_analysis_{timestamp}.json"
            try:
                with open(analysis_path, 'w') as f:
                    json.dump(analysis, f, indent=2)
                logger.info(f"AI analysis saved to {analysis_path}")
            except Exception as e:
                logger.error(f"Failed to save AI analysis: {e}")
                
            # Display AI analysis summary
            logger.info("\nAI Analysis Results:")
            logger.info(f"Risk Level: {analysis.get('risk_level', 'UNKNOWN')}")
            logger.info(f"Summary: {analysis.get('summary', 'No summary available')}")
            
            if 'recommendations' in analysis:
                logger.info("\nRecommendations:")
                for rec in analysis['recommendations']:
                    logger.info(f"- {rec}")
        else:
            logger.error("AI analysis failed or returned no results.")
    
    # Cleanup if requested
    if args.cleanup:
        logger.info("Cleaning up scan task and target...")
        await openvas.cleanup_scan(scan_results["task_id"], scan_results["target_id"])
    else:
        logger.info("Skipping cleanup. To remove the task and target, use the --cleanup flag.")
    
    logger.info("Scan completed successfully.")
    return scan_results

def run_nmap_scan(args) -> Dict[str, Any]:
    """
    Run a Nmap vulnerability scan as a fallback when OpenVAS is not available.
    
    Args:
        args: Command-line arguments
        
    Returns:
        Dictionary with scan results
    """
    try:
        from AI_MAL.core.network_scanner import NetworkScanner
        
        logger.info(f"Running Nmap vulnerability scan against {args.target}")
        
        # Configure scanner
        config = {
            "target": args.target,
            "scan_type": "aggressive",
            "vuln_detection": True,
            "service_detection": True,
            "version_detection": True,
            "os_detection": True,
            "output_dir": args.output_dir
        }
        
        # Initialize scanner
        scanner = NetworkScanner(config)
        
        # Run scan
        results = scanner.scan()
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        output_dir = Path(args.output_dir)
        json_path = output_dir / f"nmap_scan_{timestamp}.json"
        
        try:
            with open(json_path, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Nmap scan results saved to {json_path}")
        except Exception as e:
            logger.error(f"Failed to save Nmap results: {e}")
        
        return results
    
    except ImportError:
        logger.error("Failed to import NetworkScanner module")
        return {"error": "Failed to import NetworkScanner module"}
    except Exception as e:
        logger.error(f"Error during Nmap scan: {str(e)}")
        return {"error": f"Error during Nmap scan: {str(e)}"}

def main():
    """
    Main entry point for the OpenVAS scanner.
    """
    parser = argparse.ArgumentParser(
        description="AI_MAL OpenVAS vulnerability scanner"
    )
    
    parser.add_argument("target", help="Target IP address or hostname to scan")
    parser.add_argument("--scan-name", help="Name for the scan", default=None)
    parser.add_argument("--scan-config", help="Scan configuration type", 
                        choices=["full_and_fast", "full_and_very_deep", "discovery", 
                                "system_discovery", "host_discovery"],
                        default="full_and_fast")
    parser.add_argument("--username", help="OpenVAS username", default="admin")
    parser.add_argument("--password", help="OpenVAS password")
    parser.add_argument("--update-feeds", help="Update OpenVAS feeds before scanning", 
                        action="store_true")
    parser.add_argument("--ai-analysis", help="Perform AI analysis on scan results", 
                        action="store_true")
    parser.add_argument("--output-dir", help="Directory to save scan results", 
                        default="scan_results")
    parser.add_argument("--cleanup", help="Clean up scan task and target after scanning",
                        action="store_true")
    parser.add_argument("--verbose", help="Enable verbose output", 
                        action="store_true")
    parser.add_argument("--fallback-to-nmap", help="Fall back to Nmap if OpenVAS fails",
                       action="store_true", default=True)
    parser.add_argument("--no-fallback", help="Disable fallback to Nmap if OpenVAS fails",
                       action="store_true")
    
    args = parser.parse_args()
    
    try:
        results = asyncio.run(run_scan(args))
        if "error" in results:
            sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main() 