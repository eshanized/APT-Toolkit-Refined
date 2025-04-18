"""
Service Scanner Module.

This module identifies and enumerates network services running on target hosts,
including detailed information about service versions, supported features,
and potential security issues.
"""

import socket
import threading
import queue
import time
import ssl
import re
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Set, Union, Optional, Tuple, Any
from dataclasses import dataclass

from src.modules.base import BaseModule
from src.utils.network import (
    is_valid_ip, is_valid_domain, parse_target, is_port_open,
    get_hostname_from_ip, get_ip_from_hostname
)


@dataclass
class ServiceInfo:
    """Class for storing service information."""
    name: str = ""
    version: str = ""
    banner: str = ""
    protocol: str = ""
    product: str = ""
    extrainfo: str = ""
    hostname: str = ""
    ostype: str = ""
    device_type: str = ""


class ServiceScannerModule(BaseModule):
    """
    Service Scanner Module for identifying network services.
    
    Enumerates services running on target hosts, identifies versions,
    and collects detailed service information.
    """
    
    NAME = "service_scanner"
    DESCRIPTION = "Identify services running on network hosts"
    AUTHOR = "Project-N"
    
    def __init__(self):
        super().__init__()
        self.timeout = 3.0
        self.threads = 30
        self.running = False
        self.results = {}
        self.result_lock = threading.Lock()
        self.service_queue = queue.Queue()
        
        # Common service signatures for pattern matching
        self.service_signatures = {
            # SSH signature patterns
            22: [
                # OpenSSH pattern - capture version
                (re.compile(r'SSH-2.0-OpenSSH_(\d+\.\d+.*)'), "SSH", "OpenSSH"),
                (re.compile(r'SSH-1.99-OpenSSH_(\d+\.\d+.*)'), "SSH", "OpenSSH"),
                (re.compile(r'SSH-1.5-OpenSSH_(\d+\.\d+.*)'), "SSH", "OpenSSH"),
                # Generic SSH pattern
                (re.compile(r'SSH-2.0-(.*)'), "SSH", ""),
                (re.compile(r'SSH-1.99-(.*)'), "SSH", ""),
                (re.compile(r'SSH-1.5-(.*)'), "SSH", ""),
            ],
            
            # HTTP signature patterns
            80: [
                # Server header - capture web server type and version
                (re.compile(r'Server: ([^\r\n]*)'), "HTTP", ""),
                # Basic HTTP response
                (re.compile(r'HTTP/\d\.\d (\d+)'), "HTTP", ""),
            ],
            
            # HTTPS signature patterns (same as HTTP)
            443: [
                (re.compile(r'Server: ([^\r\n]*)'), "HTTPS", ""),
                (re.compile(r'HTTP/\d\.\d (\d+)'), "HTTPS", ""),
            ],
            
            # FTP signature patterns
            21: [
                # Generic FTP pattern - capture product and version
                (re.compile(r'220[ -]([^\r\n]*)'), "FTP", ""),
                # vsFTPd specific pattern
                (re.compile(r'220 \(vsFTPd (\d+\.\d+\.\d+)\)'), "FTP", "vsFTPd"),
                # ProFTPD specific pattern
                (re.compile(r'220 ProFTPD (\d+\.\d+\.\d+)'), "FTP", "ProFTPD"),
            ],
            
            # SMTP signature patterns
            25: [
                # Generic SMTP pattern
                (re.compile(r'220[ -]([^\r\n]*)SMTP'), "SMTP", ""),
                # Postfix specific pattern
                (re.compile(r'220[ -]([^\r\n]*) ESMTP Postfix'), "SMTP", "Postfix"),
                # Exim specific pattern
                (re.compile(r'220[ -]([^\r\n]*) ESMTP Exim (\d+\.\d+)'), "SMTP", "Exim"),
                # Microsoft SMTP pattern
                (re.compile(r'220[ -]([^\r\n]*) Microsoft ESMTP'), "SMTP", "Microsoft SMTP"),
            ],
            
            # POP3 signature patterns
            110: [
                # Generic POP3 pattern
                (re.compile(r'\+OK ([^\r\n]*)'), "POP3", ""),
                # Dovecot specific pattern
                (re.compile(r'\+OK \[Dovecot\]'), "POP3", "Dovecot"),
            ],
            
            # IMAP signature patterns
            143: [
                # Generic IMAP pattern
                (re.compile(r'\* OK ([^\r\n]*)'), "IMAP", ""),
                # Dovecot specific pattern
                (re.compile(r'\* OK \[CAPABILITY [^\]]*\] Dovecot'), "IMAP", "Dovecot"),
                # Cyrus specific pattern
                (re.compile(r'\* OK [^<]*<[^@>]*@([^>]*)>'), "IMAP", "Cyrus"),
            ],
            
            # MySQL signature patterns
            3306: [
                # Generic MySQL pattern
                (re.compile(r'.\x00\x00\x00\x0a(\d+\.\d+\.\d+)'), "MySQL", "MySQL"),
            ],
            
            # MS-SQL signature patterns
            1433: [
                # Generic MS-SQL pattern
                (re.compile(r'^\x04\x01'), "MSSQL", "Microsoft SQL Server"),
            ],
            
            # PostgreSQL signature patterns
            5432: [
                # Generic PostgreSQL pattern
                (re.compile(r'SFATAL'), "PostgreSQL", "PostgreSQL"),
            ],
            
            # Redis signature patterns
            6379: [
                # Generic Redis pattern
                (re.compile(r'-ERR unknown command'), "Redis", "Redis"),
                (re.compile(r'-NOAUTH Authentication required'), "Redis", "Redis"),
            ],
            
            # MongoDB signature patterns
            27017: [
                # Generic MongoDB pattern
                (re.compile(r'It looks like you are trying to access MongoDB'), "MongoDB", "MongoDB"),
            ],
            
            # RDP signature patterns
            3389: [
                # Generic RDP pattern
                (re.compile(r'^\x03\x00'), "RDP", "Microsoft Terminal Services"),
            ],
            
            # SMB signature patterns
            445: [
                # Generic SMB pattern
                (re.compile(r'^\x00\x00\x00'), "SMB", ""),
            ],
            
            # DNS signature patterns
            53: [
                # Generic DNS pattern
                (re.compile(r'^\x00\x00\x10\x00\x00'), "DNS", ""),
            ],
            
            # SNMP signature patterns
            161: [
                # Generic SNMP pattern
                (re.compile(r'^\x30'), "SNMP", ""),
            ],
            
            # NTP signature patterns
            123: [
                # Generic NTP pattern
                (re.compile(r'^\x0c'), "NTP", ""),
            ],
            
            # Telnet signature patterns
            23: [
                # Generic Telnet pattern
                (re.compile(r'^\xff\xfb\x01\xff\xfb\x03'), "Telnet", ""),
            ],
            
            # VNC signature patterns
            5900: [
                # Generic VNC pattern
                (re.compile(r'^RFB (\d+\.\d+)'), "VNC", ""),
            ],
        }
        
        # Default service names by port
        self.default_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            69: "TFTP",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            123: "NTP",
            135: "MSRPC",
            137: "NetBIOS",
            138: "NetBIOS",
            139: "NetBIOS",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            465: "SMTPS",
            500: "IKE",
            514: "Syslog",
            515: "LPD",
            587: "SMTP",
            593: "RPC",
            636: "LDAPS",
            993: "IMAPS",
            995: "POP3S",
            1080: "SOCKS",
            1194: "OpenVPN",
            1433: "MSSQL",
            1521: "Oracle",
            1723: "PPTP",
            1883: "MQTT",
            3306: "MySQL",
            3389: "RDP",
            5060: "SIP",
            5432: "PostgreSQL",
            5900: "VNC",
            5901: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB"
        }
    
    def run(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run service scanner with provided arguments.
        
        Args:
            args: Dictionary with scan parameters:
                 - target: IP address, hostname, or list of hosts
                 - ports: Port specification (e.g., "22,80,443" or "1-1024")
                 - timeout: Connection timeout in seconds
                 - threads: Number of concurrent scanning threads
                 - aggressive: Boolean to enable more aggressive probing
                 
        Returns:
            Dictionary with scan results
        """
        self.running = True
        
        # Set scan parameters
        target = args.get("target", "")
        ports = args.get("ports", "")
        self.timeout = float(args.get("timeout", self.timeout))
        self.threads = int(args.get("threads", self.threads))
        aggressive = args.get("aggressive", False)
        
        # Empty previous results
        self.results = {}
        
        # Validate target
        if not target:
            return {"status": "error", "message": "No target specified"}
        
        # Parse targets
        targets = self._parse_targets(target)
        if not targets:
            return {"status": "error", "message": f"Invalid target: {target}"}
        
        # Parse ports
        port_list = self._parse_ports(ports)
        if not port_list:
            return {"status": "error", "message": f"Invalid port specification: {ports}"}
        
        self.logger.info(f"Starting service scan on {len(targets)} host(s) and {len(port_list)} port(s)")
        
        # Create scan queue
        for target_ip in targets:
            for port in port_list:
                self.service_queue.put((target_ip, port, aggressive))
        
        # Start worker threads
        workers = []
        for _ in range(min(self.threads, self.service_queue.qsize())):
            if not self.running:
                break
                
            thread = threading.Thread(target=self._worker)
            thread.daemon = True
            thread.start()
            workers.append(thread)
        
        # Wait for all workers to finish
        self.service_queue.join()
        self.running = False
        
        # Process results
        total_services = sum(len(ports) for _, ports in self.results.items())
        
        return {
            "status": "success",
            "hosts_scanned": len(targets),
            "ports_scanned": len(port_list),
            "services_discovered": total_services,
            "results": self.results
        }
    
    def stop(self) -> None:
        """Stop the running scan."""
        self.running = False
        with self.service_queue.mutex:
            self.service_queue.queue.clear()
        self.logger.info("Service scan stopped")
    
    def _worker(self) -> None:
        """Worker thread for service scanning."""
        while self.running:
            try:
                target_ip, port, aggressive = self.service_queue.get(block=False)
            except queue.Empty:
                break
            
            try:
                # Skip if already processed (due to threading race conditions)
                with self.result_lock:
                    if target_ip in self.results and port in self.results[target_ip]:
                        self.service_queue.task_done()
                        continue
                
                # Check if port is open
                if is_port_open(target_ip, port, self.timeout):
                    # Get service information
                    service_info = self._identify_service(target_ip, port, aggressive)
                    
                    with self.result_lock:
                        if target_ip not in self.results:
                            self.results[target_ip] = {}
                            
                        self.results[target_ip][port] = {
                            "service": service_info.name,
                            "version": service_info.version,
                            "product": service_info.product,
                            "banner": service_info.banner,
                            "protocol": service_info.protocol,
                            "extrainfo": service_info.extrainfo
                        }
                        
                        self.logger.info(f"Discovered {service_info.name} on {target_ip}:{port}" + 
                                       (f" ({service_info.product} {service_info.version})" if service_info.version else ""))
            
            except Exception as e:
                self.logger.error(f"Error scanning {target_ip}:{port} - {str(e)}")
            
            finally:
                self.service_queue.task_done()
    
    def _parse_targets(self, target: str) -> List[str]:
        """
        Parse target string into list of IP addresses.
        
        Args:
            target: Target specification (IP, domain, or comma-separated list)
            
        Returns:
            List of IP addresses to scan
        """
        targets = []
        
        # Split multiple targets separated by commas
        for single_target in target.split(","):
            single_target = single_target.strip()
            
            # Parse as target (IP, domain, URL)
            parsed = parse_target(single_target)
            host = parsed['host']
            
            if is_valid_ip(host):
                targets.append(host)
            elif is_valid_domain(host):
                ip = get_ip_from_hostname(host)
                if ip:
                    targets.append(ip)
                else:
                    self.logger.error(f"Could not resolve hostname: {host}")
            else:
                self.logger.error(f"Invalid target: {single_target}")
        
        return targets
    
    def _parse_ports(self, ports: str) -> List[int]:
        """
        Parse port specification into list of port numbers.
        
        Args:
            ports: Port specification (e.g., "22,80,443" or "1-1024")
            
        Returns:
            List of port numbers to scan
        """
        result = []
        
        # If ports is empty, use common ports
        if not ports:
            return sorted(self.default_services.keys())
        
        # Handle comma-separated list with ranges
        for part in ports.split(","):
            part = part.strip()
            
            # Handle range (e.g., "1-1024")
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    
                    # Check port range limits
                    if start_port < 1 or end_port > 65535:
                        self.logger.error(f"Port range {part} out of bounds (1-65535)")
                        continue
                    
                    result.extend(range(start_port, end_port + 1))
                except ValueError:
                    self.logger.error(f"Invalid port range: {part}")
            
            # Handle single port
            else:
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        result.append(port)
                    else:
                        self.logger.error(f"Port {port} out of bounds (1-65535)")
                except ValueError:
                    self.logger.error(f"Invalid port: {part}")
        
        # Remove duplicates and sort
        return sorted(list(set(result)))
    
    def _identify_service(self, target: str, port: int, aggressive: bool) -> ServiceInfo:
        """
        Identify service running on a port.
        
        Args:
            target: Target IP address
            port: Port number
            aggressive: Whether to use more aggressive probing
            
        Returns:
            ServiceInfo object with service details
        """
        # Initialize with default values
        service_info = ServiceInfo(
            name=self.default_services.get(port, "unknown"),
            protocol="tcp"
        )
        
        # Get hostname for the target
        hostname = get_hostname_from_ip(target)
        if hostname:
            service_info.hostname = hostname
        
        # Special case for HTTPS
        if port == 443:
            ssl_info = self._get_ssl_info(target, port)
            if ssl_info:
                service_info.name = "HTTPS"
                service_info.version = ssl_info.get("version", "")
                service_info.extrainfo = ssl_info.get("cipher", "")
                service_info.banner = ssl_info.get("subject", "")
        
        # Try to get service banner
        banner = self._get_banner(target, port, aggressive)
        if banner:
            service_info.banner = banner
            
            # Match banner against known patterns
            signatures = self.service_signatures.get(port, [])
            for pattern, service_name, product_name in signatures:
                match = pattern.search(banner)
                if match:
                    if service_name:
                        service_info.name = service_name
                    if product_name:
                        service_info.product = product_name
                    
                    # Try to extract version from match
                    if match.groups():
                        version_str = match.group(1)
                        # Clean up version string
                        version_str = version_str.strip()
                        service_info.version = version_str
                    
                    break
        
        return service_info
    
    def _get_banner(self, target: str, port: int, aggressive: bool) -> str:
        """
        Try to get service banner from port.
        
        Args:
            target: Target IP address
            port: Port number
            aggressive: Whether to send probe packets to stimulate response
            
        Returns:
            Banner string if available, empty string otherwise
        """
        banner = ""
        
        try:
            # Connect to the service
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((target, port))
            
            # Different protocols need different stimuli
            if port == 80 or port == 8080:
                # HTTP request
                s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\nConnection: close\r\n\r\n")
            
            elif port == 443 or port == 8443:
                # HTTPS request (handled separately by _get_ssl_info)
                try:
                    # Try to establish SSL connection
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    ss = context.wrap_socket(s, server_hostname=target)
                    ss.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\nConnection: close\r\n\r\n")
                    banner = ss.recv(4096)
                    banner = banner.decode("utf-8", errors="ignore").strip()
                    ss.close()
                    return banner
                except:
                    pass
            
            elif port == 21:  # FTP
                # FTP server typically sends banner upon connection
                pass
            
            elif port == 22:  # SSH
                # SSH server typically sends banner upon connection
                pass
            
            elif port == 25 or port == 587:  # SMTP
                # If aggressive mode, try EHLO after receiving banner
                if aggressive:
                    time.sleep(0.1)  # Wait for banner
                    s.send(b"EHLO projectn.local\r\n")
            
            elif port == 110:  # POP3
                # If aggressive mode, try USER command after receiving banner
                if aggressive:
                    time.sleep(0.1)  # Wait for banner
                    s.send(b"USER test\r\n")
            
            elif port == 143:  # IMAP
                # If aggressive mode, try capability command after receiving banner
                if aggressive:
                    time.sleep(0.1)  # Wait for banner
                    s.send(b"A001 CAPABILITY\r\n")
            
            elif port == 3306:  # MySQL
                # MySQL server typically sends banner upon connection
                pass
            
            else:
                # Try basic stimuli for unknown ports
                if aggressive:
                    # Send blank line and common protocol probes
                    s.send(b"\r\n")
                    time.sleep(0.1)
                    s.send(b"HELP\r\n")
                    time.sleep(0.1)
                    s.send(b"?\r\n")
            
            # Receive response
            try:
                banner = s.recv(4096)
                banner = banner.decode("utf-8", errors="ignore").strip()
            except:
                # If decoding fails, try binary banner and escape it
                try:
                    binary_banner = s.recv(4096)
                    banner = repr(binary_banner)
                except:
                    pass
            
            s.close()
            
        except Exception as e:
            self.logger.debug(f"Error getting banner from {target}:{port} - {str(e)}")
        
        return banner
    
    def _get_ssl_info(self, target: str, port: int) -> Dict[str, str]:
        """
        Get SSL certificate information.
        
        Args:
            target: Target IP address
            port: SSL port (usually 443)
            
        Returns:
            Dictionary with SSL information
        """
        ssl_info = {}
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert(binary_form=True)
                    if not cert:
                        return ssl_info
                    
                    # Get SSL version
                    ssl_info["version"] = ssock.version()
                    
                    # Get cipher
                    cipher = ssock.cipher()
                    if cipher:
                        ssl_info["cipher"] = f"{cipher[0]} {cipher[1]} bits"
                    
                    # Try to extract certificate information using OpenSSL
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        
                        certificate = x509.load_der_x509_certificate(cert, default_backend())
                        
                        # Get subject
                        subject = certificate.subject.rfc4514_string()
                        ssl_info["subject"] = subject
                        
                        # Get issuer
                        issuer = certificate.issuer.rfc4514_string()
                        ssl_info["issuer"] = issuer
                        
                        # Get expiration
                        not_valid_after = certificate.not_valid_after
                        ssl_info["expires"] = not_valid_after.strftime("%Y-%m-%d")
                        
                    except ImportError:
                        # Cryptography module not available, use basic info
                        pass
                    
        except Exception as e:
            self.logger.debug(f"Error getting SSL info for {target}:{port} - {str(e)}")
        
        return ssl_info 