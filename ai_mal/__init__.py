"""AI_MAL - AI-Powered Penetration Testing Tool"""

__version__ = "0.1.0"
__author__ = "AI_MAL Team"
__license__ = "MIT"

from .core.ai_manager import AIManager
from .core.metasploit_manager import MetasploitManager
from .core.adaptive import AdaptiveNmapScanner, ScanConfig
from .core.network_discovery import NetworkDiscovery
from .core.vulnerability_scanner import VulnerabilityScanner

__all__ = [
    'AIManager',
    'MetasploitManager',
    'AdaptiveNmapScanner',
    'ScanConfig',
    'NetworkDiscovery',
    'VulnerabilityScanner'
] 