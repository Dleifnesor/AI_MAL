#!/usr/bin/env python3
"""
Test configuration for AI_MAL
"""

import os
import pytest
import asyncio
from typing import Generator

@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
def test_env():
    """Set up test environment variables."""
    os.environ["AI_MAL_MODEL"] = "qwen2.5-coder:7b"
    os.environ["AI_MAL_FALLBACK_MODEL"] = "mistral:7b"
    os.environ["AI_MAL_MSF_WORKSPACE"] = "test_workspace"
    os.environ["AI_MAL_RESOURCE_DIR"] = "test_resources"
    os.environ["AI_MAL_SCRIPT_DIR"] = "test_scripts"
    os.environ["AI_MAL_LOG_DIR"] = "test_logs"
    
    # Create test directories
    for dir_name in ["test_resources", "test_scripts", "test_logs"]:
        os.makedirs(dir_name, exist_ok=True)
    
    yield
    
    # Clean up test directories
    for dir_name in ["test_resources", "test_scripts", "test_logs"]:
        if os.path.exists(dir_name):
            for file in os.listdir(dir_name):
                os.remove(os.path.join(dir_name, file))
            os.rmdir(dir_name) 