"""
AI_MAL - AI-Powered Penetration Testing Tool
"""

__version__ = "0.1.0"
__author__ = "Dleifnesor"
__email__ = "phlegmenthusiast@gmail.com"

# Import core components
from AI_MAL.core.adaptive import AdaptiveScanner
from AI_MAL.core.ai_manager import AIManager
from AI_MAL.core.metasploit import MetasploitManager
from AI_MAL.core.script_generator import ScriptGenerator

__all__ = [
    'AdaptiveScanner',
    'AIManager',
    'MetasploitManager',
    'ScriptGenerator'
] 