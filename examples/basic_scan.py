#!/usr/bin/env python3
"""
Basic example of using AI_MAL
"""

import asyncio
from AI_MAL import AdaptiveScanner, AIManager, MetasploitManager, ScriptGenerator

async def main():
    # Target IP address
    target = "192.168.1.1"
    
    # Initialize components
    scanner = AdaptiveScanner(target)
    ai_manager = AIManager(model="qwen2.5-coder:7b", fallback_model="mistral:7b")
    metasploit = MetasploitManager()
    script_generator = ScriptGenerator()
    
    # Perform scan
    print(f"Scanning target: {target}")
    scan_results = await scanner.scan(
        stealth=False,
        services=True,
        version=True,
        os=True,
        vuln=True
    )
    
    # AI Analysis
    print("\nPerforming AI analysis...")
    analysis = await ai_manager.analyze_results(scan_results)
    print("\nAI Analysis Results:")
    print(f"Risk Level: {analysis.get('risk_level', 'UNKNOWN')}")
    print(f"Summary: {analysis.get('summary', 'No summary available')}")
    
    # Find potential exploits
    print("\nSearching for potential exploits...")
    exploits = await metasploit.find_exploits(scan_results)
    if exploits:
        print("\nFound potential exploits:")
        for exploit in exploits:
            print(f"- {exploit['name']}: {exploit['description']}")
    
    # Generate custom scripts
    print("\nGenerating custom scripts...")
    scripts = await script_generator.generate_scripts(scan_results, script_type="python")
    if scripts:
        print("\nGenerated scripts:")
        for filename in scripts.keys():
            print(f"- {filename}")

if __name__ == "__main__":
    asyncio.run(main()) 