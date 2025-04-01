"""Example of basic AI_MAL usage."""

import asyncio
import logging
from ai_mal.core.adaptive import AdaptiveNmapScanner, ScanConfig
from ai_mal.core.ai_manager import AIManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def main():
    """Run a basic scan with AI analysis."""
    # Create scan configuration
    config = ScanConfig(
        target="127.0.0.1",  # Replace with your target
        interface="eth0",     # Replace with your interface
        ports="1-1000",
        scan_type="quick",
        services=True,
        version_detection=True,
        os_detection=True,
        vulnerability_scan=True,
        output_format="json"
    )
    
    # Create scanner and AI manager
    scanner = AdaptiveNmapScanner(config)
    ai_manager = AIManager(model_name="qwen:7b")
    
    try:
        # Run scan
        logger.info("Starting scan...")
        scan_results = await scanner.run()
        
        # Perform AI analysis
        logger.info("Performing AI analysis...")
        analysis = await ai_manager.analyze_scan_results(scan_results)
        
        # Print analysis results
        logger.info("\nAI Analysis Results:")
        logger.info(f"Risk Level: {analysis['risk_level']}")
        logger.info(f"Summary: {analysis['summary']}")
        logger.info(f"\nVulnerabilities Found: {len(analysis['vulnerabilities'])}")
        for vuln in analysis['vulnerabilities']:
            logger.info(f"- {vuln['name']} ({vuln['severity']})")
            
        logger.info(f"\nAttack Vectors: {len(analysis['attack_vectors'])}")
        for vector in analysis['attack_vectors']:
            logger.info(f"- {vector}")
            
        logger.info(f"\nRecommendations: {len(analysis['recommendations'])}")
        for rec in analysis['recommendations']:
            logger.info(f"- {rec}")
            
        # Generate attack script
        logger.info("\nGenerating attack script...")
        script = await ai_manager.generate_attack_script(scan_results)
        
        # Save script
        with open("attack_script.py", "w") as f:
            f.write(script)
        logger.info("Attack script saved to attack_script.py")
        
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main()) 