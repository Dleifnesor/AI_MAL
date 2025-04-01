"""
AI_MAL - AI-Powered Penetration Testing Tool
"""

__version__ = "0.1.0"
__author__ = "Dleifnesor"
__email__ = "phlegmenthusiast@gmail.com"

from ai_mal.core.adaptive import AdaptiveScanner
from ai_mal.core.ai_manager import AIManager
from ai_mal.core.metasploit import MetasploitManager
from ai_mal.core.script_generator import ScriptGenerator

__all__ = [
    'AdaptiveScanner',
    'AIManager',
    'MetasploitManager',
    'ScriptGenerator'
] 