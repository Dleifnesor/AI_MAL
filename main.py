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
from dotenv import load_dotenv

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

class AI_MAL:
    def __init__(self, target: str, **kwargs):
        self.target = target
        self.kwargs = kwargs
        self.scanner = AdaptiveScanner(target)
        self.ai_manager = AIManager(
            model=kwargs.get('model', os.getenv('OLLAMA_MODEL', 'qwen2.5-coder:7b')),
            fallback_model=kwargs.get('fallback_model', os.getenv('OLLAMA_FALLBACK_MODEL', 'mistral:7b'))
        )
        self.metasploit = MetasploitManager() if kwargs.get('msf') else None
        self.script_generator = ScriptGenerator()

    async def run(self):
        try:
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

            # AI Analysis
            if self.kwargs.get('ai_analysis', True):
                logger.info("Analyzing scan results with AI...")
                analysis = await self.ai_manager.analyze_results(scan_results)
                logger.info("AI Analysis Results:")
                for key, value in analysis.items():
                    if isinstance(value, list):
                        logger.info(f"{key.upper()}:")
                        for item in value:
                            logger.info(f"- {item}")
                    else:
                        logger.info(f"{key.upper()}: {value}")

            # Metasploit Integration
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

            return scan_results

        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(description='AI_MAL - AI-Powered Penetration Testing Tool')
    parser.add_argument('target', help='Target IP address or range')
    
    # Basic Options
    parser.add_argument('--msf', action='store_true', help='Enable Metasploit integration')
    parser.add_argument('--exploit', action='store_true', help='Attempt exploitation of vulnerabilities')
    parser.add_argument('--model', help='Ollama model to use (default: from .env or qwen2.5-coder:7b)')
    parser.add_argument('--fallback-model', help='Fallback Ollama model (default: from .env or mistral:7b)')
    parser.add_argument('--full-auto', action='store_true', help='Enable full automation mode')
    
    # Script Generation Options
    parser.add_argument('--custom-scripts', action='store_true', help='Enable AI-powered script generation')
    parser.add_argument('--script-type', choices=['python', 'bash', 'ruby'], default='python',
                      help='Type of script to generate')
    parser.add_argument('--execute-scripts', action='store_true', help='Automatically execute generated scripts')
    
    # Scanning Options
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--continuous', action='store_true', help='Run continuous scanning')
    parser.add_argument('--delay', type=int, default=300, help='Delay between scans in seconds')
    parser.add_argument('--services', action='store_true', help='Enable service detection')
    parser.add_argument('--version', action='store_true', help='Enable version detection')
    parser.add_argument('--os', action='store_true', help='Enable OS detection')
    parser.add_argument('--vuln', action='store_true', help='Enable vulnerability scanning')
    parser.add_argument('--dos', action='store_true', help='Attempt Denial of Service attacks')
    
    # Output Options
    parser.add_argument('--output-dir', help='Output directory for results (default: from .env or scan_results)')
    parser.add_argument('--output-format', choices=['xml', 'json'], default='json',
                      help='Output format for scan results')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress output')
    
    # Advanced Options
    parser.add_argument('--iterations', type=int, default=1, help='Number of scan iterations')
    parser.add_argument('--custom-vuln', help='Path to custom vulnerability definitions')
    parser.add_argument('--ai-analysis', action='store_true', default=True,
                      help='Enable AI analysis of results')
    
    args = parser.parse_args()
    
    # Set output directory from args or environment
    output_dir = args.output_dir or os.getenv('SCAN_RESULTS_DIR', 'scan_results')
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize and run AI_MAL
    args_dict = vars(args)
    target = args_dict.pop('target')  # Remove target from args dict to avoid duplicate argument
    ai_mal = AI_MAL(target, **args_dict)

    try:
        # Run the async scan
        loop = asyncio.get_event_loop()
        scan_results = loop.run_until_complete(ai_mal.run())
        
        # Save scan results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(output_dir, f'scan_{timestamp}.json')
        
        with open(output_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
            
        logger.info(f"Scan results saved to {output_file}")
        
        # Close event loop
        loop.close()
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 