#!/usr/bin/env python3
"""
Tests for AI_MAL core functionality
"""

import asyncio
import pytest
from AI_MAL import AdaptiveScanner, AIManager, MetasploitManager, ScriptGenerator

@pytest.fixture
def target():
    return "127.0.0.1"

@pytest.fixture
def scanner(target):
    return AdaptiveScanner(target)

@pytest.fixture
def ai_manager():
    return AIManager(model="qwen2.5-coder:7b", fallback_model="gemma:1b")

@pytest.fixture
def metasploit():
    return MetasploitManager()

@pytest.fixture
def script_generator():
    return ScriptGenerator()

@pytest.mark.asyncio
async def test_scanner_initialization(scanner, target):
    """Test scanner initialization"""
    assert scanner.target == target
    assert isinstance(scanner.results, dict)

@pytest.mark.asyncio
async def test_basic_scan(scanner):
    """Test basic scan functionality"""
    results = await scanner.scan(
        stealth=True,
        services=True,
        version=True,
        os=True,
        vuln=True
    )
    assert isinstance(results, dict)
    assert "scan_info" in results
    assert "hosts" in results

@pytest.mark.asyncio
async def test_aggressive_scan(scanner):
    """Test aggressive scan functionality"""
    results = await scanner.scan(
        stealth=False,
        services=True,
        version=True,
        os=True,
        vuln=True,
        dos=True
    )
    assert isinstance(results, dict)
    assert "scan_info" in results
    assert "hosts" in results

@pytest.mark.asyncio
async def test_ai_analysis(ai_manager, scanner):
    """Test AI analysis functionality"""
    # Perform a scan first
    scan_results = await scanner.scan(
        stealth=True,
        services=True,
        version=True,
        os=True,
        vuln=True
    )
    
    # Analyze results
    analysis = await ai_manager.analyze_results(scan_results)
    assert isinstance(analysis, dict)
    assert "risk_level" in analysis
    assert "summary" in analysis

@pytest.mark.asyncio
async def test_exploit_finding(metasploit, scanner):
    """Test exploit finding functionality"""
    # Perform a scan first
    scan_results = await scanner.scan(
        stealth=True,
        services=True,
        version=True,
        os=True,
        vuln=True
    )
    
    # Find exploits
    exploits = await metasploit.find_exploits(scan_results)
    assert isinstance(exploits, list)

@pytest.mark.asyncio
async def test_script_generation(script_generator, scanner):
    """Test script generation functionality"""
    # Perform a scan first
    scan_results = await scanner.scan(
        stealth=True,
        services=True,
        version=True,
        os=True,
        vuln=True
    )
    
    # Generate scripts in different languages
    python_scripts = await script_generator.generate_scripts(
        scan_results,
        script_type="python"
    )
    assert isinstance(python_scripts, dict)
    
    bash_scripts = await script_generator.generate_scripts(
        scan_results,
        script_type="bash"
    )
    assert isinstance(bash_scripts, dict)
    
    ruby_scripts = await script_generator.generate_scripts(
        scan_results,
        script_type="ruby"
    )
    assert isinstance(ruby_scripts, dict)

@pytest.mark.asyncio
async def test_script_execution(script_generator, scanner):
    """Test script execution functionality"""
    # Perform a scan first
    scan_results = await scanner.scan(
        stealth=True,
        services=True,
        version=True,
        os=True,
        vuln=True
    )
    
    # Generate and execute scripts
    execution_results = await script_generator.execute_scripts(
        scan_results,
        script_type="python"
    )
    assert isinstance(execution_results, list)

@pytest.mark.asyncio
async def test_full_workflow(target):
    """Test full workflow integration"""
    # Initialize components
    scanner = AdaptiveScanner(target)
    ai_manager = AIManager(model="qwen2.5-coder:7b", fallback_model="gemma:1b")
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
    assert isinstance(scan_results, dict)
    
    # AI Analysis
    analysis = await ai_manager.analyze_results(scan_results)
    assert isinstance(analysis, dict)
    
    # Find exploits
    exploits = await metasploit.find_exploits(scan_results)
    assert isinstance(exploits, list)
    
    # Generate scripts
    scripts = await script_generator.generate_scripts(
        scan_results,
        script_type="python"
    )
    assert isinstance(scripts, dict)
    
    # Execute scripts
    execution_results = await script_generator.execute_scripts(
        scripts
    )
    assert isinstance(execution_results, list) 