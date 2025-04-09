"""
AI_MAL Main Module - Entry point for the penetration testing framework
"""

import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('AI_MAL')

# Import main function from scanner module
from .scanner import main

# Export main function
__all__ = ['main'] 