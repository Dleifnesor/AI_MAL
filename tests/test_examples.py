#!/usr/bin/env python3
"""
Tests for AI_MAL example scripts
"""

import os
import pytest
import asyncio
from ai_mal import AdaptiveScanner, AIManager, MetasploitManager, ScriptGenerator

@pytest.mark.asyncio
async def test_basic_example():
    """Test the basic example script functionality"""
    # Target IP address
    target = "127.0.0.1"
    
    # Initialize components
    scanner = AdaptiveScanner(target)
    ai_manager = AIManager(model="qwen2.5-coder:7b", fallback_model="mistral:7b")
    metasploit = MetasploitManager()
    script_generator = ScriptGenerator()
    
    # Perform scan
    scan_results = await scanner.scan(
        stealth=False,
        services=True,
        version=True,
        os=True,
        vuln=True
    )
    assert isinstance(scan_results, dict)
    
    # AI Analysis
    analysis = await ai_manager.analyze_results(scan_results)
    assert isinstance(analysis, dict)
    assert "risk_level" in analysis
    assert "summary" in analysis
    
    # Find potential exploits
    exploits = await metasploit.find_exploits(scan_results)
    assert isinstance(exploits, list)
    
    # Generate custom scripts
    scripts = await script_generator.generate_scripts(scan_results, script_type="python")
    assert isinstance(scripts, dict)

@pytest.mark.asyncio
async def test_advanced_example():
    """Test the advanced example script functionality"""
    # Target IP address
    target = "127.0.0.1"
    
    # Initialize components
    scanner = AdaptiveScanner(target)
    ai_manager = AIManager(model="qwen2.5-coder:7b", fallback_model="mistral:7b")
    metasploit = MetasploitManager()
    script_generator = ScriptGenerator()
    
    try:
        # Perform stealth scan
        stealth_results = await scanner.scan(
            stealth=True,
            services=True,
            version=True,
            os=True,
            vuln=True
        )
        assert isinstance(stealth_results, dict)
        
        # Perform aggressive scan
        aggressive_results = await scanner.scan(
            stealth=False,
            services=True,
            version=True,
            os=True,
            vuln=True,
            dos=True
        )
        assert isinstance(aggressive_results, dict)
        
        # Merge results
        scan_results = {
            "stealth": stealth_results,
            "aggressive": aggressive_results
        }
        
        # AI Analysis
        analysis = await ai_manager.analyze_results(scan_results)
        assert isinstance(analysis, dict)
        
        # Print analysis results
        assert "risk_level" in analysis
        assert "summary" in analysis
        
        if 'vulnerabilities' in analysis:
            assert isinstance(analysis['vulnerabilities'], list)
        
        if 'attack_vectors' in analysis:
            assert isinstance(analysis['attack_vectors'], list)
        
        if 'recommendations' in analysis:
            assert isinstance(analysis['recommendations'], list)
        
        # Find and run Metasploit exploits
        exploits = await metasploit.find_exploits(scan_results)
        assert isinstance(exploits, list)
        
        if exploits:
            # Run exploits
            exploit_results = await metasploit.run_exploits(exploits)
            assert isinstance(exploit_results, list)
        
        # Generate custom scripts in multiple languages
        # Python scripts
        python_scripts = await script_generator.generate_scripts(
            scan_results,
            script_type="python"
        )
        assert isinstance(python_scripts, dict)
        
        # Bash scripts
        bash_scripts = await script_generator.generate_scripts(
            scan_results,
            script_type="bash"
        )
        assert isinstance(bash_scripts, dict)
        
        # Ruby scripts
        ruby_scripts = await script_generator.generate_scripts(
            scan_results,
            script_type="ruby"
        )
        assert isinstance(ruby_scripts, dict)
        
        # Execute generated scripts
        execution_results = await script_generator.execute_scripts(
            scan_results,
            script_type="python"
        )
        assert isinstance(execution_results, list)
        
    except Exception as e:
        pytest.fail(f"Advanced example test failed: {e}")

@pytest.mark.asyncio
async def test_example_output_files():
    """Test that example scripts create expected output files"""
    # Target IP address
    target = "127.0.0.1"
    
    # Initialize components
    scanner = AdaptiveScanner(target)
    ai_manager = AIManager(model="qwen2.5-coder:7b", fallback_model="mistral:7b")
    metasploit = MetasploitManager()
    script_generator = ScriptGenerator()
    
    # Perform scan
    scan_results = await scanner.scan(
        stealth=True,
        services=True,
        version=True,
        os=True,
        vuln=True
    )
    
    # Generate scripts
    scripts = await script_generator.generate_scripts(scan_results, script_type="python")
    
    # Check that script files were created
    for filename in scripts.keys():
        assert os.path.exists(filename)
    
    # Execute scripts
    execution_results = await script_generator.execute_scripts(
        scan_results,
        script_type="python"
    )
    
    # Check that output files were created
    for result in execution_results:
        if 'output_file' in result:
            assert os.path.exists(result['output_file']) 