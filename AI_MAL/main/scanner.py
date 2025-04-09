"""
AI_MAL Scanner Module - Core scanning functionality
"""

import sys
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from ..core.adaptive import AdaptiveScanner
from ..core.ai_manager import AIManager
from ..core.metasploit import MetasploitManager
from ..core.script_generator import ScriptGenerator

def main(target: str = None, scan_type: str = None, **kwargs) -> Dict[str, Any]:
    """
    Main entry point for AI_MAL scanning functionality.
    
    Args:
        target: Target IP or hostname to scan
        scan_type: Type of scan to perform
        **kwargs: Additional scan parameters
        
    Returns:
        Dict containing scan results
    """
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger('AI_MAL')
    
    try:
        # Initialize components
        scanner = AdaptiveScanner()
        ai_manager = AIManager()
        msf_manager = MetasploitManager()
        script_gen = ScriptGenerator()
        
        # Build scan configuration
        config = {
            'target': target,
            'scan_type': scan_type,
            **kwargs
        }
        
        # Run scan
        results = scanner.run_scan(config)
        
        # Process results with AI if enabled
        if kwargs.get('ai_analysis', False):
            ai_results = ai_manager.analyze_results(results)
            results['ai_analysis'] = ai_results
            
        # Generate scripts if requested
        if kwargs.get('generate_scripts', False):
            scripts = script_gen.generate_scripts(results)
            results['generated_scripts'] = scripts
            
        return results
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        raise

if __name__ == '__main__':
    # Parse command line arguments
    import argparse
    
    parser = argparse.ArgumentParser(description='AI_MAL - AI-Powered Penetration Testing Framework')
    parser.add_argument('target', help='Target IP or hostname to scan')
    parser.add_argument('--scan-type', choices=['quick', 'full', 'stealth'], default='quick',
                      help='Type of scan to perform')
    parser.add_argument('--ai-analysis', action='store_true',
                      help='Enable AI analysis of scan results')
    parser.add_argument('--generate-scripts', action='store_true',
                      help='Generate exploitation scripts based on findings')
    
    args = parser.parse_args()
    
    try:
        results = main(
            target=args.target,
            scan_type=args.scan_type,
            ai_analysis=args.ai_analysis,
            generate_scripts=args.generate_scripts
        )
        print(results)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1) 