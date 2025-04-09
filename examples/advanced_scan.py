#!/usr/bin/env python3
"""
Advanced example of using AI_MAL with all features
"""

import asyncio
import logging
from AI_MAL import AdaptiveScanner, AIManager, MetasploitManager, ScriptGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def main():
    # Target IP address
    target = "192.168.1.1"
    
    # Initialize components
    scanner = AdaptiveScanner(target)
    ai_manager = AIManager(model="artifish/llama3.2-uncensored", fallback_model="gemma3:1b")
    metasploit = MetasploitManager()
    script_generator = ScriptGenerator()
    
    try:
        # Perform stealth scan
        logger.info(f"Starting stealth scan of target: {target}")
        stealth_results = await scanner.scan(
            stealth=True,
            services=True,
            version=True,
            os=True,
            vuln=True
        )
        
        # Perform aggressive scan
        logger.info("Starting aggressive scan...")
        aggressive_results = await scanner.scan(
            stealth=False,
            services=True,
            version=True,
            os=True,
            vuln=True,
            dos=True
        )
        
        # Merge results
        scan_results = {
            "stealth": stealth_results,
            "aggressive": aggressive_results
        }
        
        # AI Analysis
        logger.info("Performing AI analysis...")
        analysis = await ai_manager.analyze_results(scan_results)
        
        # Print analysis results
        logger.info("\nAI Analysis Results:")
        logger.info(f"Risk Level: {analysis.get('risk_level', 'UNKNOWN')}")
        logger.info(f"Summary: {analysis.get('summary', 'No summary available')}")
        
        if 'vulnerabilities' in analysis:
            logger.info("\nVulnerabilities Found:")
            for vuln in analysis['vulnerabilities']:
                logger.info(f"- {vuln.get('name', 'Unknown')} ({vuln.get('severity', 'Unknown')})")
                logger.info(f"  Description: {vuln.get('description', 'No description available')}")
        
        if 'attack_vectors' in analysis:
            logger.info("\nPotential Attack Vectors:")
            for vector in analysis['attack_vectors']:
                logger.info(f"- {vector}")
        
        if 'recommendations' in analysis:
            logger.info("\nSecurity Recommendations:")
            for rec in analysis['recommendations']:
                logger.info(f"- {rec}")
        
        # Find and run Metasploit exploits
        logger.info("\nSearching for potential exploits...")
        exploits = await metasploit.find_exploits(scan_results)
        
        if exploits:
            logger.info("\nFound potential exploits:")
            for exploit in exploits:
                logger.info(f"- {exploit['name']}: {exploit['description']}")
            
            # Run exploits
            logger.info("\nAttempting to run exploits...")
            exploit_results = await metasploit.run_exploits(exploits)
            
            if exploit_results:
                logger.info("\nExploit Results:")
                for result in exploit_results:
                    logger.info(f"- {result['exploit']}: {result['status']}")
                    if 'output' in result:
                        logger.info(f"  Output: {result['output']}")
        
        # Generate custom scripts in multiple languages
        logger.info("\nGenerating custom scripts...")
        
        # Python scripts
        python_scripts = await script_generator.generate_scripts(
            scan_results,
            script_type="python"
        )
        if python_scripts:
            logger.info("\nGenerated Python scripts:")
            for filename in python_scripts.keys():
                logger.info(f"- {filename}")
        
        # Bash scripts
        bash_scripts = await script_generator.generate_scripts(
            scan_results,
            script_type="bash"
        )
        if bash_scripts:
            logger.info("\nGenerated Bash scripts:")
            for filename in bash_scripts.keys():
                logger.info(f"- {filename}")
        
        # Ruby scripts
        ruby_scripts = await script_generator.generate_scripts(
            scan_results,
            script_type="ruby"
        )
        if ruby_scripts:
            logger.info("\nGenerated Ruby scripts:")
            for filename in ruby_scripts.keys():
                logger.info(f"- {filename}")
        
        # Execute generated scripts
        logger.info("\nExecuting generated scripts...")
        execution_results = await script_generator.execute_scripts(
            python_scripts
        )
        
        if execution_results:
            logger.info("\nScript Execution Results:")
            for result in execution_results:
                logger.info(f"- {result['script']}: {result['status']}")
                if 'output' in result:
                    logger.info(f"  Output: {result['output']}")
        
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main()) 