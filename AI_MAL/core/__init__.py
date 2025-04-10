"""
AI_MAL core package initialization.
"""

import os
import sys
import logging
from pathlib import Path

# Get the absolute path to the AI_MAL directory
AI_MAL_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(AI_MAL_DIR))

# Configure core logging
logger = logging.getLogger('AI_MAL.core')

# Ensure required directories exist
required_dirs = ['logs', 'scan_results', 'workspaces']
for dir_name in required_dirs:
    dir_path = AI_MAL_DIR / dir_name
    dir_path.mkdir(exist_ok=True)

# Import core components with proper error handling
try:
    from .network_scanner import NetworkScanner
except ImportError as e:
    logger.error(f"Failed to import NetworkScanner: {e}")
    raise

try:
    from .ai_manager import AIManager
except ImportError as e:
    logger.error(f"Failed to import AIManager: {e}")
    raise

try:
    from .script_generator import ScriptGenerator
except ImportError as e:
    logger.error(f"Failed to import ScriptGenerator: {e}")
    raise

try:
    from .metasploit import MetasploitManager
except ImportError as e:
    logger.error(f"Failed to import MetasploitManager: {e}")
    raise

try:
    from .adaptive import AdaptiveScanner
except ImportError as e:
    logger.error(f"Failed to import AdaptiveScanner: {e}")
    raise

# Export core components
__all__ = [
    'NetworkScanner',
    'AIManager',
    'ScriptGenerator',
    'MetasploitManager',
    'AdaptiveScanner'
] 