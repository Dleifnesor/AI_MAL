#!/usr/bin/env python3
"""
Example of using AI_MAL with OpenVAS vulnerability scanning
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import AI_MAL components
try:
    from AI_MAL import AI_MAL
    from AI_MAL.core.openvas_manager import OpenVASManager
except ImportError:
    logger.error("Could not import AI_MAL. Make sure it's installed correctly.")
    sys.exit(1)

async def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="AI_MAL OpenVAS vulnerability scanner")
    parser.add_argument("target", help="Target IP address or hostname to scan")
    parser.add_argument("--scan-name", help="Name for the scan", default=None)
    parser.add_argument("--scan-config", help="Scan configuration type", 
                        choices=["full_and_fast", "full_and_very_deep", "discovery", 
                                "system_discovery", "host_discovery"],
                        default="full_and_fast")
    parser.add_argument("--update-feeds", help="Update OpenVAS feeds before scanning", 
                        action="store_true")
    parser.add_argument("--ai-analysis", help="Perform AI analysis on scan results", 
                        action="store_true")
    parser.add_argument("--output-dir", help="Directory to save scan results", 
                        default="scan_results")
    parser.add_argument("--verbose", help="Enable verbose output", 
                        action="store_true")
    
    args = parser.parse_args()
    
    # Configure output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Set up log file in output directory
    file_handler = logging.FileHandler(output_dir / f"openvas_scan_{datetime.now().strftime('%Y%m%d-%H%M%S')}.log")
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)
    
    # Configure verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
    
    # Initialize OpenVAS manager
    openvas_config = {
        "results_dir": str(output_dir)
    }
    openvas = OpenVASManager(config=openvas_config)
    
    # Initialize AI_MAL
    ai_mal_config = {
        "target": args.target,
        "verbose": args.verbose,
        "ai_analysis": args.ai_analysis,
        "scan_config": args.scan_config,
        "results_dir": str(output_dir)
    }
    ai_mal = AI_MAL(config=ai_mal_config)
    
    # Check OpenVAS status
    logger.info("Checking OpenVAS status...")
    status = await openvas.check_openvas_status()
    
    if not status["installed"]:
        logger.error("OpenVAS is not installed. Please install OpenVAS first.")
        sys.exit(1)
    
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
            sys.exit(1)
    
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
        sys.exit(1)
    
    # Display scan summary
    logger.info(f"Scan completed. Found {len(scan_results.get('vulnerabilities', []))} vulnerabilities.")
    
    # Save scan results as JSON
    json_path = output_dir / f"openvas_scan_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    try:
        import json
        with open(json_path, 'w') as f:
            json.dump(scan_results, f, indent=2)
        logger.info(f"Scan results saved to {json_path}")
    except Exception as e:
        logger.error(f"Failed to save scan results: {e}")
    
    # Perform AI analysis if requested
    if args.ai_analysis:
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
        analysis = await ai_mal.ai_manager.analyze_results(ai_mal_scan_data)
        
        # Display AI analysis results
        if analysis:
            logger.info("\nAI Analysis Results:")
            logger.info(f"Risk Level: {analysis.get('risk_level', 'UNKNOWN')}")
            logger.info(f"Summary: {analysis.get('summary', 'No summary available')}")
            
            if 'recommendations' in analysis:
                logger.info("\nRecommendations:")
                for rec in analysis['recommendations']:
                    logger.info(f"- {rec}")
            
            # Save analysis as JSON
            analysis_path = output_dir / f"ai_analysis_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            try:
                with open(analysis_path, 'w') as f:
                    json.dump(analysis, f, indent=2)
                logger.info(f"AI analysis saved to {analysis_path}")
            except Exception as e:
                logger.error(f"Failed to save AI analysis: {e}")
        else:
            logger.error("AI analysis failed or returned no results.")
    
    # Cleanup
    logger.info("Cleaning up scan task and target...")
    await openvas.cleanup_scan(scan_results["task_id"], scan_results["target_id"])
    
    logger.info("Scan completed successfully.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        sys.exit(1) 