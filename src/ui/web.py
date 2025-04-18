"""
Web UI module for Project-N.

This module provides a web interface for Project-N using Flask.
"""

import os
import json
import threading
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.serving import make_server

from ..modules import PortScannerModule, VulnerabilityScannerModule
from ..utils.network import is_valid_ip, is_valid_domain, is_valid_port, parse_target

class WebServer:
    """Web server for Project-N web interface."""
    
    def __init__(self, host='127.0.0.1', port=8080):
        """
        Initialize the web server.
        
        Args:
            host (str): Host to bind the server to.
            port (int): Port to bind the server to.
        """
        self.host = host
        self.port = port
        self.app = Flask(
            __name__, 
            template_folder=os.path.join(os.path.dirname(__file__), '..', 'templates'),
            static_folder=os.path.join(os.path.dirname(__file__), '..', 'static')
        )
        self.server = None
        self.server_thread = None
        self.running = False
        self._setup_routes()
        
    def _setup_routes(self):
        """Set up Flask routes."""
        
        @self.app.route('/')
        def index():
            return render_template('index.html')
        
        @self.app.route('/api/scan/port', methods=['POST'])
        def port_scan():
            data = request.json
            target = data.get('target', '')
            ports = data.get('ports', '1-1000')
            
            # Validate input
            parsed = parse_target(target)
            if not parsed:
                return jsonify({'error': 'Invalid target format'}), 400
                
            protocol, host, _ = parsed
            
            if not (is_valid_ip(host) or is_valid_domain(host)):
                return jsonify({'error': 'Invalid host'}), 400
            
            # Initialize scanner
            scanner = PortScannerModule()
            
            # Start scan
            result = scanner.scan(host, ports)
            
            return jsonify({
                'target': host,
                'results': result
            })
        
        @self.app.route('/api/scan/vulnerability', methods=['POST'])
        def vulnerability_scan():
            data = request.json
            target = data.get('target', '')
            
            # Validate input
            parsed = parse_target(target)
            if not parsed:
                return jsonify({'error': 'Invalid target format'}), 400
                
            protocol, host, port = parsed
            
            if not (is_valid_ip(host) or is_valid_domain(host)):
                return jsonify({'error': 'Invalid host'}), 400
            
            if port and not is_valid_port(port):
                return jsonify({'error': 'Invalid port'}), 400
            
            # Initialize scanner
            scanner = VulnerabilityScannerModule()
            
            # Start scan
            if port:
                result = scanner.scan_target(f"{host}:{port}")
            else:
                result = scanner.scan_target(host)
            
            return jsonify({
                'target': host,
                'results': result
            })
    
    def start(self):
        """Start the web server in a separate thread."""
        if self.running:
            return
        
        self.server = make_server(self.host, self.port, self.app)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        self.running = True
        print(f"Web server started at http://{self.host}:{self.port}")
    
    def stop(self):
        """Stop the web server."""
        if not self.running:
            return
        
        self.server.shutdown()
        self.server_thread.join()
        self.running = False
        print("Web server stopped")

def create_server(host='127.0.0.1', port=8080):
    """
    Create a new web server instance.
    
    Args:
        host (str): Host to bind the server to.
        port (int): Port to bind the server to.
        
    Returns:
        WebServer: The web server instance.
    """
    return WebServer(host, port) 