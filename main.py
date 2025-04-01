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

from ai_mal.core.adaptive import AdaptiveScanner
from ai_mal.core.ai_manager import AIManager
from ai_mal.core.metasploit import MetasploitManager
from ai_mal.core.script_generator import ScriptGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ai_mal.log'),
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
            model=kwargs.get('model', 'qwen2.5-coder:7b'),
            fallback_model=kwargs.get('fallback_model', 'mistral:7b')
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
                analysis = await self.ai_manager.analyze_results(scan_results)
                logger.info("AI Analysis Results:")
                logger.info(analysis)

            # Metasploit Integration
            if self.metasploit and self.kwargs.get('exploit', False):
                exploits = await self.metasploit.find_exploits(scan_results)
                if exploits:
                    logger.info("Found potential Metasploit exploits:")
                    for exploit in exploits:
                        logger.info(f"- {exploit}")
                    
                    if self.kwargs.get('full_auto', False):
                        await self.metasploit.run_exploits(exploits)

            # Custom Script Generation
            if self.kwargs.get('custom_scripts', False):
                script_type = self.kwargs.get('script_type', 'python')
                scripts = await self.script_generator.generate_scripts(
                    scan_results,
                    script_type=script_type
                )
                
                if self.kwargs.get('execute_scripts', False):
                    await self.script_generator.execute_scripts(scripts)

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
    parser.add_argument('--model', default='qwen2.5-coder:7b', help='Ollama model to use')
    parser.add_argument('--fallback-model', default='mistral:7b', help='Fallback Ollama model')
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
    parser.add_argument('--output-dir', default='scan_results', help='Output directory for results')
    parser.add_argument('--output-format', choices=['xml', 'json'], default='json',
                      help='Output format for scan results')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress output')
    
    # Advanced Options
    parser.add_argument('--iterations', type=int, default=1, help='Number of scan iterations')
    parser.add_argument('--custom-vuln', help='Path to custom vulnerability definitions')
    parser.add_argument('--ai-analysis', action='store_true', default=True,
                      help='Enable AI analysis of results')
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize and run AI_MAL
    ai_mal = AI_MAL(args.target, **vars(args))
    
    try:
        results = asyncio.run(ai_mal.run())
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(args.output_dir, f'scan_results_{timestamp}.{args.output_format}')
        
        if args.output_format == 'json':
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        else:
            import xml.etree.ElementTree as ET
            root = ET.Element('scan_results')
            # Convert results to XML format
            # ... (implement XML conversion)
            tree = ET.ElementTree(root)
            tree.write(output_file)
            
        logger.info(f"Results saved to {output_file}")
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 