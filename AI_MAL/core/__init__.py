"""
AI_MAL core package initialization.
"""

import os
import logging
from pathlib import Path

# Configure core logging
logger = logging.getLogger('AI_MAL.core')

# Ensure required directories exist
required_dirs = ['logs', 'scan_results', 'workspaces']
for dir_name in required_dirs:
    os.makedirs(dir_name, exist_ok=True)

# Import core components
try:
    from .network_scanner import NetworkScanner
    from .ai_manager import AIManager
    from .script_generator import ScriptGenerator
    from .metasploit import MetasploitManager
    from .adaptive import AdaptiveScanner
except ImportError as e:
    logger.error(f"Failed to import core components: {e}")
    raise

__all__ = [
    'NetworkScanner',
    'AIManager',
    'ScriptGenerator',
    'MetasploitManager',
    'AdaptiveScanner'
] 