"""
Vulnerability Scanner Module.

This module scans a target for common vulnerabilities 
including open ports, service vulnerabilities, and web application issues.
"""

import socket
import time
import threading
import concurrent.futures
import re
import ssl
import requests
import json
from typing import Dict, List, Any, Optional, Union, Tuple
from urllib.parse import urlparse

from src.core.base_module import BaseModule
from src.utils.network import is_valid_ip, is_valid_domain, is_valid_url
from src.utils.logger import get_logger


class VulnScannerModule(BaseModule):
    """Vulnerability scanner module."""
    
    def __init__(self, **kwargs):
        """Initialize vulnerability scanner module."""
        super().__init__(
            name="Vulnerability Scanner",
            description="Scans targets for common vulnerabilities",
            version="1.0.0",
            **kwargs
        )
        
        # Scanner configuration
        self.timeout = kwargs.get('timeout', 5)
        self.threads = kwargs.get('threads', 10)
        self.aggressive = kwargs.get('aggressive', False)
        self.ports = kwargs.get('ports', [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                                         993, 995, 1723, 3306, 3389, 5900, 8080, 8443])
        self.web_paths = kwargs.get('web_paths', [
            "/", "/admin", "/login", "/wp-admin", "/administrator", "/phpmyadmin",
            "/jenkins", "/manager/html", "/solr", "/api", "/console", "/wp-login.php",
            "/.git", "/.env", "/config"
        ])
        
        # Common vulnerabilities to check
        self.vuln_checks = {
            "ssh": self._check_ssh_vulnerabilities,
            "ftp": self._check_ftp_vulnerabilities,
            "http": self._check_http_vulnerabilities,
            "https": self._check_https_vulnerabilities,
            "smb": self._check_smb_vulnerabilities,
            "mysql": self._check_mysql_vulnerabilities,
            "mssql": self._check_mssql_vulnerabilities
        }
        
        # Service to port mapping
        self.service_ports = {
            "ftp": 21,
            "ssh": 22,
            "telnet": 23,
            "smtp": 25,
            "dns": 53,
            "http": 80,
            "pop3": 110,
            "rpc": 111,
            "msrpc": 135,
            "netbios": 139,
            "imap": 143,
            "https": 443,
            "smb": 445,
            "imaps": 993,
            "pop3s": 995,
            "vpn": 1723,
            "mysql": 3306,
            "rdp": 3389,
            "vnc": 5900,
            "http-alt": 8080,
            "https-alt": 8443
        }
        
        # Vulnerability database (simplified for example)
        self.vuln_db = {
            "ssl": {
                "heartbleed": {
                    "name": "Heartbleed",
                    "description": "OpenSSL heartbeat extension information disclosure (CVE-2014-0160)",
                    "severity": "high"
                },
                "poodle": {
                    "name": "POODLE",
                    "description": "SSL 3.0 vulnerability allows attackers to decrypt secure communications (CVE-2014-3566)",
                    "severity": "medium"
                },
                "freak": {
                    "name": "FREAK",
                    "description": "Factoring Attack on RSA-EXPORT Keys vulnerability (CVE-2015-0204)",
                    "severity": "medium"
                }
            },
            "web": {
                "sql_injection": {
                    "name": "SQL Injection",
                    "description": "Possibility of SQL injection vulnerability",
                    "severity": "high"
                },
                "xss": {
                    "name": "Cross-Site Scripting (XSS)",
                    "description": "Possibility of XSS vulnerability",
                    "severity": "medium"
                },
                "directory_traversal": {
                    "name": "Directory Traversal",
                    "description": "Possibility of directory traversal vulnerability",
                    "severity": "high"
                },
                "exposed_git": {
                    "name": "Exposed Git Repository",
                    "description": "Git repository exposed, could lead to source code disclosure",
                    "severity": "medium"
                },
                "exposed_env": {
                    "name": "Exposed Environment File",
                    "description": "Environment file exposed, could lead to credential disclosure",
                    "severity": "high"
                }
            },
            "ssh": {
                "weak_cipher": {
                    "name": "Weak SSH Cipher",
                    "description": "SSH server configured with weak ciphers",
                    "severity": "medium"
                }
            },
            "ftp": {
                "anonymous_login": {
                    "name": "Anonymous FTP Login",
                    "description": "FTP server allows anonymous login",
                    "severity": "medium"
                }
            },
            "smb": {
                "eternalblue": {
                    "name": "EternalBlue",
                    "description": "SMB Remote Code Execution Vulnerability (MS17-010)",
                    "severity": "critical"
                }
            }
        }
    
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Run vulnerability scanner on target.
        
        Args:
            target: Target to scan (IP, domain, or URL)
            **kwargs: Additional options
        
        Returns:
            Dict with scan results
        """
        self.running = True
        self.results = {
            "target": target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": [],
            "open_ports": [],
            "services": {},
            "web_vulnerabilities": [],
            "ssl_vulnerabilities": [],
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        
        self.logger.info(f"Starting vulnerability scan on {target}")
        self.update_status(f"Starting vulnerability scan on {target}")
        self.update_progress(0)
        
        # Validate target
        if not (is_valid_ip(target) or is_valid_domain(target) or is_valid_url(target)):
            self.logger.error(f"Invalid target: {target}")
            return {"error": f"Invalid target: {target}"}
        
        # Parse target
        target_info = self._parse_target(target)
        self.logger.info(f"Parsed target: {target_info}")
        
        try:
            # Step 1: Port scanning (20%)
            self.update_status("Scanning for open ports...")
            open_ports = self._scan_ports(target_info["host"])
            self.results["open_ports"] = open_ports
            self.update_progress(20)
            
            if not self.running:
                return self.results
            
            # Step 2: Service detection (40%)
            self.update_status("Detecting services...")
            services = self._detect_services(target_info["host"], open_ports)
            self.results["services"] = services
            self.update_progress(40)
            
            if not self.running:
                return self.results
            
            # Step 3: Vulnerability scanning (70%)
            self.update_status("Scanning for vulnerabilities...")
            self._scan_vulnerabilities(target_info, services)
            self.update_progress(70)
            
            if not self.running:
                return self.results
            
            # Step 4: Web application scanning if applicable (90%)
            if target_info["is_web"] or 80 in open_ports or 443 in open_ports:
                self.update_status("Scanning web application...")
                self._scan_web_vulnerabilities(target_info)
            
            self.update_progress(90)
            
            # Step 5: Generate summary (100%)
            self.update_status("Generating scan summary...")
            self._generate_summary()
            self.update_progress(100)
            
            self.logger.info(f"Vulnerability scan completed for {target}")
            self.update_status("Scan completed")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"Error scanning target: {str(e)}")
            self.results["error"] = str(e)
            return self.results
    
    def stop(self):
        """Stop the vulnerability scanner."""
        self.running = False
        self.logger.info("Vulnerability scanner stopped")
        self.update_status("Scan stopped")
    
    def _parse_target(self, target: str) -> Dict[str, Any]:
        """
        Parse target to extract host, port, and protocol.
        
        Args:
            target: Target to parse
        
        Returns:
            Dict with parsed target information
        """
        result = {
            "original": target,
            "host": target,
            "port": None,
            "protocol": None,
            "is_web": False,
            "path": "/"
        }
        
        # Check if target is URL
        if is_valid_url(target):
            parsed = urlparse(target)
            result["host"] = parsed.netloc.split(':')[0]
            result["protocol"] = parsed.scheme
            result["is_web"] = True
            result["path"] = parsed.path if parsed.path else "/"
            
            if ':' in parsed.netloc:
                result["port"] = int(parsed.netloc.split(':')[1])
            else:
                result["port"] = 443 if parsed.scheme == 'https' else 80
        
        # Check if host:port format
        elif ':' in target and not target.startswith('['):
            host, port = target.split(':', 1)
            if port.isdigit() and 1 <= int(port) <= 65535:
                result["host"] = host
                result["port"] = int(port)
        
        return result
    
    def _scan_ports(self, host: str) -> List[int]:
        """
        Scan target for open ports.
        
        Args:
            host: Host to scan
        
        Returns:
            List of open ports
        """
        open_ports = []
        port_queue = self.ports if self.ports else range(1, 1025)
        
        def scan_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return port if result == 0 else None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(scan_port, port) for port in port_queue]
            for future in concurrent.futures.as_completed(futures):
                if not self.running:
                    break
                
                port = future.result()
                if port:
                    self.logger.debug(f"Found open port: {port}")
                    open_ports.append(port)
                    self.add_result(f"Open port found: {port}")
        
        return sorted(open_ports)
    
    def _detect_services(self, host: str, ports: List[int]) -> Dict[str, Any]:
        """
        Detect services running on open ports.
        
        Args:
            host: Host to scan
            ports: List of open ports
        
        Returns:
            Dict with service information
        """
        services = {}
        
        for port in ports:
            if not self.running:
                break
                
            service_info = self._probe_service(host, port)
            if service_info:
                services[port] = service_info
        
        return services
    
    def _probe_service(self, host: str, port: int) -> Dict[str, Any]:
        """
        Probe a specific port to identify the service.
        
        Args:
            host: Host to scan
            port: Port to probe
        
        Returns:
            Dict with service information
        """
        # Default service mapping
        default_services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpc",
            135: "msrpc",
            139: "netbios",
            143: "imap",
            443: "https",
            445: "smb",
            993: "imaps",
            995: "pop3s",
            1723: "vpn",
            3306: "mysql",
            3389: "rdp",
            5900: "vnc",
            8080: "http-alt",
            8443: "https-alt"
        }
        
        service_name = default_services.get(port, "unknown")
        service_info = {
            "name": service_name,
            "version": None,
            "banner": None
        }
        
        try:
            # Attempt to grab banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Special case for HTTP/HTTPS
            if port == 80 or port == 8080:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
                service_name = "http"
            elif port == 443 or port == 8443:
                # Wrap socket for SSL
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
                    service_name = "https"
                except:
                    service_name = "https"
                    
            # Try to receive banner
            try:
                banner = sock.recv(1024).strip()
                if banner:
                    service_info["banner"] = banner.decode('utf-8', errors='ignore')
                    
                    # Try to extract version from banner
                    version_match = re.search(r'([a-zA-Z]+)[/ ]([0-9.]+)', service_info["banner"])
                    if version_match:
                        possible_service = version_match.group(1).lower()
                        if possible_service in ["http", "ssh", "ftp", "smtp", "imap", "pop3"]:
                            service_name = possible_service
                        service_info["version"] = version_match.group(2)
            except:
                pass
                
            sock.close()
            
        except Exception as e:
            pass
        
        service_info["name"] = service_name
        return service_info
    
    def _scan_vulnerabilities(self, target_info: Dict[str, Any], services: Dict[int, Dict[str, Any]]):
        """
        Scan for vulnerabilities based on detected services.
        
        Args:
            target_info: Parsed target information
            services: Detected services
        """
        for port, service_info in services.items():
            if not self.running:
                break
                
            service_name = service_info["name"]
            
            # Check if we have vulnerability checks for this service
            if service_name in self.vuln_checks:
                self.update_status(f"Checking {service_name} vulnerabilities...")
                try:
                    vulns = self.vuln_checks[service_name](target_info["host"], port, service_info)
                    if vulns:
                        for vuln in vulns:
                            self.results["vulnerabilities"].append(vuln)
                            severity = vuln.get("severity", "info")
                            self.add_result(f"Found {severity} vulnerability: {vuln['name']} on {service_name}")
                except Exception as e:
                    self.logger.error(f"Error checking {service_name} vulnerabilities: {str(e)}")
    
    def _scan_web_vulnerabilities(self, target_info: Dict[str, Any]):
        """
        Scan for web application vulnerabilities.
        
        Args:
            target_info: Parsed target information
        """
        host = target_info["host"]
        port = target_info["port"]
        protocol = target_info["protocol"] or "http"
        
        if not port:
            port = 443 if protocol == "https" else 80
        
        base_url = f"{protocol}://{host}:{port}"
        
        # Check for common vulnerabilities
        for path in self.web_paths:
            if not self.running:
                break
                
            url = f"{base_url}{path}"
            self.logger.debug(f"Checking web path: {url}")
            
            try:
                response = requests.get(url, timeout=self.timeout, verify=False, 
                                      allow_redirects=True)
                
                # Check if path exists
                if response.status_code == 200:
                    self.logger.debug(f"Found accessible path: {path}")
                    
                    # Check for specific vulnerabilities based on path
                    if path == "/.git":
                        vuln = self.vuln_db["web"]["exposed_git"].copy()
                        vuln["url"] = url
                        self.results["web_vulnerabilities"].append(vuln)
                        self.results["vulnerabilities"].append(vuln)
                    
                    elif path == "/.env":
                        vuln = self.vuln_db["web"]["exposed_env"].copy()
                        vuln["url"] = url
                        self.results["web_vulnerabilities"].append(vuln)
                        self.results["vulnerabilities"].append(vuln)
                    
                    # Basic XSS check
                    if self.aggressive:
                        xss_test_url = f"{url}?q=<script>alert(1)</script>"
                        xss_response = requests.get(xss_test_url, timeout=self.timeout, verify=False)
                        if "<script>alert(1)</script>" in xss_response.text:
                            vuln = self.vuln_db["web"]["xss"].copy()
                            vuln["url"] = url
                            self.results["web_vulnerabilities"].append(vuln)
                            self.results["vulnerabilities"].append(vuln)
                
                # Check HTTP headers for information disclosure
                server_header = response.headers.get("Server")
                if server_header:
                    self.results["services"][port if port in self.results["services"] else "web"] = {
                        "name": "http",
                        "version": server_header,
                        "banner": f"Server: {server_header}"
                    }
                
            except requests.exceptions.RequestException:
                pass
        
        # Check SSL vulnerabilities if using HTTPS
        if protocol == "https":
            self._check_ssl_vulnerabilities(host, port)
    
    def _check_ssh_vulnerabilities(self, host: str, port: int, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check for SSH vulnerabilities.
        
        Args:
            host: Target host
            port: SSH port
            service_info: Service information
            
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # Check for weak ciphers (simplified for example)
        if service_info.get("banner") and "SSH-2.0" in service_info["banner"]:
            if service_info.get("version") and service_info["version"].startswith(("5.", "6.")):
                vuln = self.vuln_db["ssh"]["weak_cipher"].copy()
                vuln["port"] = port
                vuln["details"] = f"SSH server version {service_info['version']} might support weak ciphers"
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_ftp_vulnerabilities(self, host: str, port: int, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check for FTP vulnerabilities.
        
        Args:
            host: Target host
            port: FTP port
            service_info: Service information
            
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # Check for anonymous login
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            
            try:
                ftp.login('anonymous', 'anonymous@test.com')
                vuln = self.vuln_db["ftp"]["anonymous_login"].copy()
                vuln["port"] = port
                vuln["details"] = "FTP server allows anonymous login"
                vulnerabilities.append(vuln)
                ftp.quit()
            except:
                pass
                
        except Exception as e:
            self.logger.debug(f"Error checking FTP: {str(e)}")
        
        return vulnerabilities
    
    def _check_http_vulnerabilities(self, host: str, port: int, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check for HTTP vulnerabilities.
        
        Args:
            host: Target host
            port: HTTP port
            service_info: Service information
            
        Returns:
            List of found vulnerabilities
        """
        # Web vulnerabilities are checked in _scan_web_vulnerabilities
        return []
    
    def _check_https_vulnerabilities(self, host: str, port: int, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check for HTTPS vulnerabilities.
        
        Args:
            host: Target host
            port: HTTPS port
            service_info: Service information
            
        Returns:
            List of found vulnerabilities
        """
        # SSL vulnerabilities are checked in _check_ssl_vulnerabilities
        return []
    
    def _check_smb_vulnerabilities(self, host: str, port: int, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check for SMB vulnerabilities.
        
        Args:
            host: Target host
            port: SMB port
            service_info: Service information
            
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # Simple check for EternalBlue (MS17-010) - in reality this would be more complex
        if port == 445:
            # This is a simulated check for example purposes
            # In a real implementation, this would involve specific packet crafting
            
            if self.aggressive:
                # Simplified simulation - this is not a real check
                # In a real scanner, we would check SMB version and send specific packets
                vuln = self.vuln_db["smb"]["eternalblue"].copy()
                vuln["port"] = port
                vuln["details"] = "Potential vulnerability to MS17-010 (EternalBlue)"
                vuln["confidence"] = "low"  # This is a simulated check with low confidence
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_mysql_vulnerabilities(self, host: str, port: int, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check for MySQL vulnerabilities.
        
        Args:
            host: Target host
            port: MySQL port
            service_info: Service information
            
        Returns:
            List of found vulnerabilities
        """
        # Simplified for example
        return []
    
    def _check_mssql_vulnerabilities(self, host: str, port: int, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check for MSSQL vulnerabilities.
        
        Args:
            host: Target host
            port: MSSQL port
            service_info: Service information
            
        Returns:
            List of found vulnerabilities
        """
        # Simplified for example
        return []
    
    def _check_ssl_vulnerabilities(self, host: str, port: int) -> List[Dict[str, Any]]:
        """
        Check for SSL vulnerabilities.
        
        Args:
            host: Target host
            port: SSL port
            
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to server
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert(binary_form=True)
                    if not cert:
                        return []
                    
                    # Check SSL/TLS version
                    version = ssock.version()
                    
                    # Check for vulnerabilities based on version
                    if version == "SSLv3":
                        vuln = self.vuln_db["ssl"]["poodle"].copy()
                        vuln["port"] = port
                        vuln["details"] = f"Server supports SSLv3, vulnerable to POODLE attack"
                        vulnerabilities.append(vuln)
                        self.results["ssl_vulnerabilities"].append(vuln)
                    
                    # Cipher suite checks (simplified)
                    cipher = ssock.cipher()
                    if cipher and 'EXPORT' in cipher[0]:
                        vuln = self.vuln_db["ssl"]["freak"].copy()
                        vuln["port"] = port
                        vuln["details"] = f"Server supports EXPORT cipher suites, vulnerable to FREAK attack"
                        vulnerabilities.append(vuln)
                        self.results["ssl_vulnerabilities"].append(vuln)
        
        except Exception as e:
            self.logger.debug(f"Error checking SSL: {str(e)}")
        
        return vulnerabilities
    
    def _generate_summary(self):
        """Generate summary of vulnerabilities found."""
        # Count vulnerabilities by severity
        for vuln in self.results["vulnerabilities"]:
            severity = vuln.get("severity", "info").lower()
            if severity in self.results["summary"]:
                self.results["summary"][severity] += 1
        
        self.logger.info(f"Scan summary: "
                       f"{self.results['summary']['critical']} critical, "
                       f"{self.results['summary']['high']} high, "
                       f"{self.results['summary']['medium']} medium, "
                       f"{self.results['summary']['low']} low, "
                       f"{self.results['summary']['info']} info") 