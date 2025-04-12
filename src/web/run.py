#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL Web Interface Runner
===========================

This script runs the AI_MAL web interface as a standalone application.
"""

import os
import sys
import argparse
import subprocess

# Add the parent directory to the path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.app import app, socketio

def check_requirements():
    """Check if all required packages are installed"""
    required_packages = ['flask', 'flask-socketio', 'eventlet', 'werkzeug']
    
    try:
        import flask
        import flask_socketio
        import eventlet
    except ImportError as e:
        print(f"Missing required package: {e}")
        print("Installing required packages...")
        subprocess.call([sys.executable, '-m', 'pip', 'install'] + required_packages)
        print("Please restart the application.")
        sys.exit(1)

def main():
    """Main entry point for the web interface"""
    parser = argparse.ArgumentParser(description='Run the AI_MAL web interface')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8443, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--ssl', action='store_true', help='Enable SSL')
    parser.add_argument('--cert', default='cert.pem', help='SSL certificate file')
    parser.add_argument('--key', default='key.pem', help='SSL key file')
    
    args = parser.parse_args()
    
    # Check requirements
    check_requirements()
    
    print(f"Starting AI_MAL Web Interface on http{'s' if args.ssl else ''}://{args.host}:{args.port}")
    
    # Generate SSL certificate if needed and requested
    if args.ssl and (not os.path.exists(args.cert) or not os.path.exists(args.key)):
        print("Generating self-signed SSL certificate...")
        subprocess.call(['openssl', 'req', '-new', '-x509', '-keyout', args.key, 
                        '-out', args.cert, '-days', '365', '-nodes', '-subj', 
                        '/C=US/ST=None/L=None/O=AI_MAL/CN=localhost'])
    
    # Run the server
    if args.ssl:
        socketio.run(app, host=args.host, port=args.port, debug=args.debug,
                    certfile=args.cert, keyfile=args.key,
                    allow_unsafe_werkzeug=args.debug)
    else:
        socketio.run(app, host=args.host, port=args.port, debug=args.debug,
                    allow_unsafe_werkzeug=args.debug)

if __name__ == '__main__':
    main() 