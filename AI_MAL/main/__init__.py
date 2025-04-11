"""
AI_MAL main package initialization.
"""

import os
import sys
import logging
from pathlib import Path

# Get the absolute path to the AI_MAL directory
AI_MAL_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(AI_MAL_DIR))

# Create logs directory if it doesn't exist
logs_dir = AI_MAL_DIR / 'logs'
logs_dir.mkdir(exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(str(logs_dir / 'ai_mal.log')),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('AI_MAL')

# Import main function from scanner module
try:
    from .scanner import main
except ImportError as e:
    logger.error(f"Failed to import scanner module: {e}")
    raise

# Export main function
__all__ = ['main'] 