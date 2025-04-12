#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL Web Interface
===================

Standalone command to run the AI_MAL web interface.
"""

import os
import sys
import subprocess

# Add the AI_MAL root directory to the Python path
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(root_dir)

def main():
    """Main entry point for the AI_MAL Web Interface"""
    # Check if required packages are installed
    try:
        import flask
        import flask_socketio
        import eventlet
    except ImportError as e:
        print(f"Missing required package: {e}")
        print("Installing required packages...")
        subprocess.call([sys.executable, '-m', 'pip', 'install', 'flask', 'flask-socketio', 'eventlet', 'werkzeug'])
        print("Restarting application...")
        os.execv(sys.executable, [sys.executable] + sys.argv)
    
    # Import the run module
    from src.web.run import main as run_web
    
    # Print welcome message
    print("=" * 60)
    print("AI_MAL Web Interface")
    print("=" * 60)
    print("An AI-powered penetration testing platform")
    print("Integrating with OpenVAS, Metasploit, and Ollama")
    print("=" * 60)
    
    # Run the web interface
    run_web()

if __name__ == "__main__":
    main() 