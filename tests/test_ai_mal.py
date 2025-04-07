"""Tests for AI_MAL functionality."""

import os
import pytest
import asyncio
from typing import Dict, Any

from AI_MAL.core.adaptive import AdaptiveNmapScanner, ScanConfig
from AI_MAL.core.ai_manager import AIManager

@pytest.fixture
def scan_config():
    """Create a test scan configuration."""
    return ScanConfig(
        target="127.0.0.1",
        interface="lo",
        ports="1-100",
        scan_type="quick",
        output_dir="test_results",
        services=True,
        version_detection=True,
        os_detection=True,
        vulnerability_scan=True,
        output_format="json"
    )

@pytest.fixture
def ai_manager():
    """Create an AI manager instance."""
    return AIManager(model_name="qwen:7b")

@pytest.mark.asyncio
async def test_scan_with_ai_analysis(scan_config, ai_manager):
    """Test scanning with AI analysis."""
    # Create scanner
    scanner = AdaptiveNmapScanner(scan_config)
    
    # Run scan
    scan_results = await scanner.run()
    
    # Verify scan results
    assert scan_results is not None
    assert "scan_results" in scan_results
    assert "vulnerability_results" in scan_results
    assert "targets" in scan_results
    
    # Perform AI analysis
    analysis = await ai_manager.analyze_scan_results(scan_results)
    
    # Verify analysis results
    assert analysis is not None
    assert "vulnerabilities" in analysis
    assert "attack_vectors" in analysis
    assert "recommendations" in analysis
    assert "risk_level" in analysis
    assert "summary" in analysis

@pytest.mark.asyncio
async def test_attack_script_generation(scan_config, ai_manager):
    """Test attack script generation."""
    # Create scanner
    scanner = AdaptiveNmapScanner(scan_config)
    
    # Run scan
    scan_results = await scanner.run()
    
    # Generate attack script
    script = await ai_manager.generate_attack_script(scan_results)
    
    # Verify script
    assert script is not None
    assert isinstance(script, str)
    assert "#!/usr/bin/env python3" in script
    assert "import logging" in script
    assert "def main():" in script

@pytest.mark.asyncio
async def test_fallback_model(scan_config):
    """Test fallback model functionality."""
    # Create AI manager with invalid model
    ai_manager = AIManager(model_name="invalid_model")
    
    # Create scanner
    scanner = AdaptiveNmapScanner(scan_config)
    
    # Run scan
    scan_results = await scanner.run()
    
    # Attempt analysis (should use fallback model)
    analysis = await ai_manager.analyze_scan_results(scan_results)
    
    # Verify analysis results
    assert analysis is not None
    assert "vulnerabilities" in analysis
    assert "attack_vectors" in analysis
    assert "recommendations" in analysis
    assert "risk_level" in analysis
    assert "summary" in analysis

def test_cleanup():
    """Clean up test files."""
    if os.path.exists("test_results"):
        for file in os.listdir("test_results"):
            os.remove(os.path.join("test_results", file))
        os.rmdir("test_results") 