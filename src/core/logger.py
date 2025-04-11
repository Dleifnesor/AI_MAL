#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL Logger Module
===================

This module handles logging for the AI_MAL tool.
"""

import os
import logging
import logging.handlers
from datetime import datetime

def setup_logger(log_level=logging.INFO, log_file="logs/AI_MAL.log", quiet=False):
    """
    Set up the logger for the application.
    
    Args:
        log_level (int): The logging level (e.g., logging.DEBUG, logging.INFO)
        log_file (str): Path to the log file
        quiet (bool): If True, suppress console output
    
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logger
    logger = logging.getLogger("AI_MAL")
    logger.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create log directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # File handler
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10485760, backupCount=5)  # 10MB per file, max 5 files
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Console handler (if not quiet)
    if not quiet:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger

class LoggerWrapper:
    """
    Logger wrapper class for components that need to log.
    Provides a consistent interface for logging.
    """
    
    def __init__(self, name, parent_logger=None):
        """
        Initialize a logger wrapper.
        
        Args:
            name (str): Name of the component
            parent_logger (logging.Logger, optional): Parent logger to use
        """
        if parent_logger:
            self.logger = parent_logger.getChild(name)
        else:
            self.logger = logging.getLogger(f"AI_MAL.{name}")
    
    def debug(self, message):
        """Log debug message."""
        self.logger.debug(message)
    
    def info(self, message):
        """Log info message."""
        self.logger.info(message)
    
    def warning(self, message):
        """Log warning message."""
        self.logger.warning(message)
    
    def error(self, message):
        """Log error message."""
        self.logger.error(message)
    
    def critical(self, message):
        """Log critical message."""
        self.logger.critical(message)
    
    def exception(self, message):
        """Log exception message with traceback."""
        self.logger.exception(message) 