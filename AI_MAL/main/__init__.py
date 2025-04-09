"""
AI_MAL main package initialization.
"""

import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ai_mal.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('AI_MAL')

# Ensure logs directory exists
os.makedirs('logs', exist_ok=True)

# Import main function from scanner module
from .scanner import main

# Export main function
__all__ = ['main'] 