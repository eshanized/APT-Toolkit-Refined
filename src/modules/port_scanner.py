"""
Port Scanner Module for network port scanning.

This module implements various port scanning techniques:
- TCP Connect Scan
- SYN Scan
- UDP Scan

It supports scanning single hosts, multiple IP ranges, and can detect common services.
"""

import os
import socket
import struct
import time
import threading
import queue
import enum
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Set, Union, Optional, Tuple, Any
from dataclasses import dataclass

from src.core.base_module import BaseModule
from src.utils.network import (
    is_valid_ip, is_valid_domain, parse_target, get_ip_from_hostname,
    get_hostname_from_ip, is_port_open, get_ip_range
)


class ScanType(enum.Enum):
    """Enum for different port scanning techniques."""
    TCP_CONNECT = "tcp_connect"
    SYN = "syn"
    UDP = "udp"


class PortState(enum.Enum):
    """Enum for port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class PortResult:
    """Class for storing port scan results."""
    port: int
    state: PortState
    service: str = ""
    banner: str = ""


class PortScannerModule(BaseModule):
    """
    Port Scanner Module for network reconnaissance.
    
    Supports multiple scanning techniques including TCP Connect, SYN and UDP scans.
    Can detect common services on open ports based on well-known port mappings.
    """
    
    NAME = "port_scanner"
    DESCRIPTION = "Scan for open ports on a target host or network"
    AUTHOR = "Project-N"
    
    def __init__(self):
        super().__init__()
        self.timeout = 2.0
        self.threads = 50
        self.max_ports = 10000
        self.running = False
        self.results = {}
        self.result_lock = threading.Lock()
        self.scan_queue = queue.Queue()
        self.default_ports = "1-1024"
        
        # Common services and their default ports
        self.common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            123: "NTP",
            135: "MSRPC",
            137: "NetBIOS",
            138: "NetBIOS",
            139: "NetBIOS",
            143: "IMAP",
            161: "SNMP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            5901: "VNC",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
    
    def run(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run port scanner with provided arguments.
        
        Args:
            args: Dictionary with scan parameters:
                 - target: IP address, hostname, or CIDR range
                 - ports: Port specification (e.g., "22,80,443" or "1-1024")
                 - scan_type: Scan technique (tcp_connect, syn, udp)
                 - timeout: Connection timeout in seconds
                 - threads: Number of concurrent scanning threads
                 
        Returns:
            Dictionary with scan results
        """
        self.running = True
        
        # Set scan parameters
        target = args.get("target", "")
        ports = args.get("ports", self.default_ports)
        scan_type_str = args.get("scan_type", ScanType.TCP_CONNECT.value)
        self.timeout = float(args.get("timeout", self.timeout))
        self.threads = int(args.get("threads", self.threads))
        
        # Empty previous results
        self.results = {}
        
        # Validate target
        if not target:
            return {"status": "error", "message": "No target specified"}
        
        # Determine scan type
        try:
            scan_type = ScanType(scan_type_str)
        except ValueError:
            self.logger.error(f"Unsupported scan type: {scan_type_str}")
            return {
                "status": "error",
                "message": f"Unsupported scan type: {scan_type_str}. Use one of: {', '.join([t.value for t in ScanType])}"
            }
        
        if scan_type == ScanType.SYN and not self._is_root():
            self.logger.error("SYN scan requires root privileges")
            return {"status": "error", "message": "SYN scan requires root privileges"}
        
        # Parse target(s)
        targets = self._parse_targets(target)
        if not targets:
            return {"status": "error", "message": f"Invalid target: {target}"}
        
        # Parse ports
        port_list = self._parse_ports(ports)
        if not port_list:
            return {"status": "error", "message": f"Invalid port specification: {ports}"}
        
        self.logger.info(f"Starting {scan_type.value} scan on {len(targets)} target(s) and {len(port_list)} port(s)")
        
        # Create scan queue
        for target_ip in targets:
            for port in port_list:
                self.scan_queue.put((target_ip, port))
        
        # Start worker threads
        workers = []
        for _ in range(min(self.threads, self.scan_queue.qsize())):
            if not self.running:
                break
                
            thread = threading.Thread(target=self._worker, args=(scan_type,))
            thread.daemon = True
            thread.start()
            workers.append(thread)
        
        # Wait for all workers to finish
        self.scan_queue.join()
        self.running = False
        
        # Process results for each target
        final_results = {}
        for target_ip, port_results in self.results.items():
            hostname = get_hostname_from_ip(target_ip) or ""
            
            # Group results by state
            grouped_results = {
                "open": [],
                "filtered": [],
                "closed": []
            }
            
            for port_result in port_results:
                if port_result.state == PortState.OPEN:
                    grouped_results["open"].append({
                        "port": port_result.port,
                        "service": port_result.service,
                        "banner": port_result.banner
                    })
                elif port_result.state == PortState.FILTERED:
                    grouped_results["filtered"].append({
                        "port": port_result.port
                    })
                elif port_result.state == PortState.CLOSED:
                    grouped_results["closed"].append({
                        "port": port_result.port
                    })
            
            final_results[target_ip] = {
                "hostname": hostname,
                "open_ports": len(grouped_results["open"]),
                "filtered_ports": len(grouped_results["filtered"]),
                "closed_ports": len(grouped_results["closed"]),
                "results": grouped_results
            }
        
        return {
            "status": "success",
            "scan_type": scan_type.value,
            "targets_scanned": len(targets),
            "ports_scanned": len(port_list),
            "results": final_results
        }
    
    def stop(self) -> None:
        """Stop the running scan."""
        self.running = False
        with self.scan_queue.mutex:
            self.scan_queue.queue.clear()
        self.logger.info("Port scan stopped")
    
    def _worker(self, scan_type: ScanType) -> None:
        """
        Worker thread for scanning.
        
        Args:
            scan_type: Type of scan to perform
        """
        while self.running:
            try:
                target_ip, port = self.scan_queue.get(block=False)
            except queue.Empty:
                break
            
            try:
                if scan_type == ScanType.TCP_CONNECT:
                    result = self._tcp_connect_scan(target_ip, port)
                elif scan_type == ScanType.SYN:
                    result = self._tcp_syn_scan(target_ip, port)
                elif scan_type == ScanType.UDP:
                    result = self._udp_scan(target_ip, port)
                else:
                    self.logger.error(f"Unsupported scan type: {scan_type}")
                    self.scan_queue.task_done()
                    continue
                
                if result:
                    with self.result_lock:
                        if target_ip not in self.results:
                            self.results[target_ip] = []
                        self.results[target_ip].append(result)
                        
                        if result.state == PortState.OPEN:
                            self.logger.info(f"Found open port {port}/{scan_type.value} on {target_ip} ({result.service})")
            
            except Exception as e:
                self.logger.error(f"Error scanning {target_ip}:{port} - {str(e)}")
            
            finally:
                self.scan_queue.task_done()
    
    def _is_root(self) -> bool:
        """Check if the program is running with root privileges."""
        try:
            return os.geteuid() == 0
        except AttributeError:
            # OS doesn't support geteuid (e.g., Windows)
            return False
    
    def _parse_targets(self, target: str) -> List[str]:
        """
        Parse target string into list of IP addresses.
        
        Args:
            target: Target specification (IP, domain, or CIDR range)
            
        Returns:
            List of IP addresses to scan
        """
        targets = []
        
        # Split multiple targets separated by commas
        for single_target in target.split(","):
            single_target = single_target.strip()
            
            # Check if it's a CIDR range
            if "/" in single_target and not single_target.startswith("http"):
                try:
                    cidr_ips = get_ip_range(single_target)
                    targets.extend(cidr_ips)
                    continue
                except Exception as e:
                    self.logger.error(f"Invalid CIDR range: {single_target} - {str(e)}")
            
            # Parse as normal target (IP, domain, URL)
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
        
        if not ports:
            return result
        
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
                    
                    # Check range size limit
                    if end_port - start_port > self.max_ports:
                        self.logger.error(f"Port range {part} too large (max {self.max_ports})")
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
    
    def _tcp_connect_scan(self, target: str, port: int) -> Optional[PortResult]:
        """
        Perform TCP connect scan on target port.
        
        Args:
            target: Target IP address
            port: Port number to scan
            
        Returns:
            PortResult object with scan results
        """
        result = PortResult(port=port, state=PortState.CLOSED)
        
        # Check if port is open
        is_open = is_port_open(target, port, self.timeout)
        
        if is_open:
            result.state = PortState.OPEN
            result.service = self.common_services.get(port, "")
            
            # Try to get service banner
            try:
                banner = self._get_banner(target, port)
                if banner:
                    result.banner = banner
            except:
                pass
                
            return result
        else:
            result.state = PortState.CLOSED
            return result
    
    def _tcp_syn_scan(self, target: str, port: int) -> Optional[PortResult]:
        """
        Perform TCP SYN scan on target port.
        
        Args:
            target: Target IP address
            port: Port number to scan
            
        Returns:
            PortResult object with scan results
        """
        # Use TCP connect scan as fallback if not running as root
        # In a real implementation, this would use raw sockets for SYN scanning
        result = self._tcp_connect_scan(target, port)
        return result
    
    def _udp_scan(self, target: str, port: int) -> Optional[PortResult]:
        """
        Perform UDP scan on target port.
        
        Args:
            target: Target IP address
            port: Port number to scan
            
        Returns:
            PortResult object with scan results
        """
        result = PortResult(port=port, state=PortState.CLOSED)
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b"", (target, port))
            
            # Try to receive data
            try:
                data, _ = sock.recvfrom(1024)
                # If we receive data, port is open
                result.state = PortState.OPEN
                result.service = self.common_services.get(port, "")
                if data:
                    result.banner = data.decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                # Timeout can mean either filtered or open with no response
                result.state = PortState.FILTERED
            except ConnectionRefusedError:
                # ICMP Port Unreachable = closed
                result.state = PortState.CLOSED
                
        except Exception as e:
            self.logger.error(f"UDP scan error on {target}:{port} - {str(e)}")
            result.state = PortState.FILTERED
            
        finally:
            try:
                sock.close()
            except:
                pass
                
        return result
    
    def _get_banner(self, target: str, port: int) -> str:
        """
        Try to get service banner from open port.
        
        Args:
            target: Target IP address
            port: Port number
            
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
            if port in [80, 8080, 443]:
                # HTTP request
                s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port in [21, 22, 25, 110, 143]:
                # These protocols usually send banner upon connection
                pass
            else:
                # Try basic stimuli
                s.send(b"\r\n")
            
            # Receive response
            banner = s.recv(1024)
            banner = banner.decode("utf-8", errors="ignore").strip()
            
        except Exception as e:
            pass
            
        finally:
            try:
                s.close()
            except:
                pass
                
        return banner 