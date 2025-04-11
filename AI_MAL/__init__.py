"""
AI_MAL - AI-Powered Penetration Testing Framework
"""

__version__ = "0.1.0"
__author__ = "Dleifnesor"
__email__ = "phlegmenthusiast@gmail.com"

# Import core components
from AI_MAL.core.adaptive import AdaptiveScanner
from AI_MAL.core.ai_manager import AIManager
from AI_MAL.core.metasploit import MetasploitManager
from AI_MAL.core.script_generator import ScriptGenerator
from AI_MAL.core.network_scanner import NetworkScanner
from AI_MAL.core.openvas_manager import OpenVASManager

# Import main function from scanner module
from AI_MAL.main import AI_MAL

__all__ = [
    'AI_MAL',
    'AdaptiveScanner',
    'AIManager',
    'MetasploitManager',
    'ScriptGenerator',
    'NetworkScanner',
    'OpenVASManager'
] 