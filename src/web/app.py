#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL Web Interface
===================

A web interface for the AI_MAL tool, integrated with OpenVAS's UI.
"""

import os
import sys
import json
import logging
import datetime
import subprocess
import threading
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from flask_socketio import SocketIO, emit

# Add the parent directory to the path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import AI_MAL modules
from core.scanner import Scanner
from core.vuln_scanner import VulnScanner
from core.msf_integration import MSFIntegration
from core.ai_analysis import AIAnalyzer
from core.script_generator import ScriptGenerator
from core.logger import setup_logger

# Configure logging
logger = setup_logger('web_interface', level=logging.INFO)

# Initialize Flask application
app = Flask(__name__, 
    static_folder='static',
    template_folder='templates'
)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False

# Initialize Socket.IO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
scan_status = {}
active_scans = {}
scan_results = {}
vuln_results = {}
analysis_results = {}
current_tasks = {}

# Class for handling AI_MAL operations in the web interface
class WebAIMAL:
    def __init__(self):
        self.scanner = Scanner()
        self.vuln_scanner = VulnScanner()
        self.msf = MSFIntegration()
        self.ai_analyzer = AIAnalyzer()
        self.script_generator = ScriptGenerator()
    
    def start_scan(self, target, options):
        """Start a scan with the given options"""
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Update scan status
        scan_status[scan_id] = {
            'target': target,
            'options': options,
            'status': 'running',
            'start_time': datetime.datetime.now().isoformat(),
            'progress': 0,
            'complete': False
        }
        
        # Create a thread for the scan
        scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, target, options)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return scan_id
    
    def _run_scan(self, scan_id, target, options):
        """Run the scan in a separate thread"""
        try:
            # Update progress
            self._update_progress(scan_id, 10, "Initializing scan...")
            
            # Start network scan
            self._update_progress(scan_id, 20, "Running network scan...")
            hosts = self.scanner.scan_network(target, options.get('scan_type', 'quick'))
            scan_results[scan_id] = hosts
            
            # Run vulnerability scan if requested
            if options.get('vuln', False):
                self._update_progress(scan_id, 40, "Running vulnerability scan...")
                vuln_results[scan_id] = self.vuln_scanner.scan_with_openvas(hosts)
            
            # Run MSF integration if requested
            if options.get('msf', False):
                self._update_progress(scan_id, 60, "Running Metasploit integration...")
                self.msf.find_exploits(hosts)
            
            # Run AI analysis if requested
            if options.get('ai_analysis', False):
                self._update_progress(scan_id, 80, "Running AI analysis...")
                analysis_results[scan_id] = self.ai_analyzer.analyze_scan_results(
                    hosts, 
                    vuln_results.get(scan_id, {}),
                    options.get('model', None)
                )
            
            # Generate custom scripts if requested
            if options.get('custom_scripts', False):
                self._update_progress(scan_id, 90, "Generating custom scripts...")
                self.script_generator.generate_scripts(
                    hosts,
                    vuln_results.get(scan_id, {}),
                    options.get('script_type', 'python')
                )
            
            # Mark scan as complete
            self._update_progress(scan_id, 100, "Scan complete!")
            scan_status[scan_id]['status'] = 'completed'
            scan_status[scan_id]['complete'] = True
            scan_status[scan_id]['end_time'] = datetime.datetime.now().isoformat()
            
        except Exception as e:
            logger.error(f"Error during scan {scan_id}: {str(e)}")
            scan_status[scan_id]['status'] = 'error'
            scan_status[scan_id]['error'] = str(e)
            self._update_progress(scan_id, 100, f"Error: {str(e)}")
    
    def _update_progress(self, scan_id, progress, message):
        """Update scan progress and emit socket event"""
        scan_status[scan_id]['progress'] = progress
        scan_status[scan_id]['message'] = message
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'progress': progress,
            'message': message
        })
        logger.info(f"Scan {scan_id}: {message} ({progress}%)")

# Initialize the WebAIMAL instance
web_aimal = WebAIMAL()

# Routes

@app.route('/')
def index():
    """Main dashboard page"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if using OpenVAS credentials
        if username == os.environ.get('GVM_USERNAME', 'admin'):
            if password == os.environ.get('GVM_PASSWORD', 'admin'):
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('index'))
        
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/scan/new', methods=['GET', 'POST'])
def new_scan():
    """Create a new scan"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        target = request.form.get('target')
        options = {
            'scan_type': request.form.get('scan_type', 'quick'),
            'vuln': 'vuln' in request.form,
            'msf': 'msf' in request.form,
            'ai_analysis': 'ai_analysis' in request.form,
            'model': request.form.get('model', None),
            'custom_scripts': 'custom_scripts' in request.form,
            'script_type': request.form.get('script_type', 'python')
        }
        
        scan_id = web_aimal.start_scan(target, options)
        return redirect(url_for('scan_status', scan_id=scan_id))
    
    return render_template('new_scan.html')

@app.route('/scan/status/<scan_id>')
def scan_status(scan_id):
    """Show status of a specific scan"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if scan_id not in scan_status:
        flash('Scan not found')
        return redirect(url_for('scans'))
    
    return render_template('scan_status.html', scan_id=scan_id, status=scan_status[scan_id])

@app.route('/scans')
def scans():
    """List all scans"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    return render_template('scans.html', scans=scan_status)

@app.route('/results/<scan_id>')
def results(scan_id):
    """Show detailed results for a scan"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if scan_id not in scan_status:
        flash('Scan not found')
        return redirect(url_for('scans'))
    
    return render_template('results.html', 
        scan_id=scan_id, 
        status=scan_status[scan_id],
        hosts=scan_results.get(scan_id, {}),
        vulnerabilities=vuln_results.get(scan_id, {}),
        analysis=analysis_results.get(scan_id, {})
    )

@app.route('/vulnerabilities')
def vulnerabilities():
    """Show all vulnerabilities across scans"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    all_vulns = {}
    for scan_id, vulns in vuln_results.items():
        all_vulns[scan_id] = vulns
    
    return render_template('vulnerabilities.html', vulnerabilities=all_vulns)

@app.route('/openvas')
def openvas_redirect():
    """Redirect to OpenVAS web interface"""
    return redirect('https://localhost:9392')

@app.route('/api/scan/status/<scan_id>', methods=['GET'])
def api_scan_status(scan_id):
    """API endpoint for scan status"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_status[scan_id])

@app.route('/api/scan/results/<scan_id>', methods=['GET'])
def api_scan_results(scan_id):
    """API endpoint for scan results"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan not found'}), 404
    
    results = {
        'status': scan_status[scan_id],
        'hosts': scan_results.get(scan_id, {}),
        'vulnerabilities': vuln_results.get(scan_id, {}),
        'analysis': analysis_results.get(scan_id, {})
    }
    
    return jsonify(results)

# Socket.IO events

@socketio.on('connect')
def socket_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def socket_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('request_status')
def socket_request_status(data):
    """Send current status to client"""
    scan_id = data.get('scan_id')
    if scan_id and scan_id in scan_status:
        emit('scan_update', {
            'scan_id': scan_id,
            'progress': scan_status[scan_id]['progress'],
            'message': scan_status[scan_id].get('message', '')
        })

# Main entry point
if __name__ == '__main__':
    # Add required packages to requirements.txt if needed
    required_packages = ['flask', 'flask-socketio', 'werkzeug']
    
    # Check if we should add the packages to requirements.txt
    try:
        import flask, flask_socketio
    except ImportError:
        print("Installing required packages for web interface...")
        subprocess.call([sys.executable, '-m', 'pip', 'install'] + required_packages)
    
    # Start the web server
    print("Starting AI_MAL Web Interface...")
    socketio.run(app, host='0.0.0.0', port=8443, debug=True, allow_unsafe_werkzeug=True) 