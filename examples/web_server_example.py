#!/usr/bin/env python3
"""
Web Server Example for Project-N

This example demonstrates how to start and use the web server interface
for Project-N. It initializes a WebServer instance and runs it.

Usage:
    python3 web_server_example.py
"""

import sys
import time
import argparse
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).resolve().parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.ui.web import create_server

def main():
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Start the Project-N web interface')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind the server to')
    parser.add_argument('--debug', action='store_true', help='Run the server in debug mode')
    args = parser.parse_args()
    
    # Create and start the web server
    server = create_server(host=args.host, port=args.port, debug=args.debug)
    
    try:
        print(f"* Web server running at http://{args.host}:{args.port}")
        print("* Press CTRL+C to stop the server")
        
        # Start the server
        server.start()
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()
        print("Server stopped.")

if __name__ == "__main__":
    main() 