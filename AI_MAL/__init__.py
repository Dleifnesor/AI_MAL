"""
AI_MAL - AI-Powered Penetration Testing Framework
"""

__version__ = "0.1.0"
__author__ = "Dleifnesor"
__email__ = "phlegmenthusiast@gmail.com"

# Import core components
from .core.adaptive import AdaptiveScanner
from .core.ai_manager import AIManager
from .core.metasploit import MetasploitManager
from .core.script_generator import ScriptGenerator

# Import main function from scanner module
from .main.scanner import main

__all__ = [
    'AdaptiveScanner',
    'AIManager',
    'MetasploitManager',
    'ScriptGenerator',
    'main'
] 