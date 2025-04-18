"""
Port Scanner Module.

This module provides port scanning functionality with different scanning techniques
including TCP connect, SYN scan, and UDP scan.
"""

import socket
import time
import struct
import random
import threading
import concurrent.futures
from typing import Dict, List, Any, Optional, Union, Tuple, Set
from enum import Enum

from src.core.base_module import BaseModule
from src.utils.network import is_valid_ip, is_valid_domain, is_valid_port


class ScanType(Enum):
    """Scan types enum."""
    TCP_CONNECT = "tcp_connect"  # Basic TCP connect scan
    TCP_SYN = "tcp_syn"          # SYN scan (requires root)
    UDP = "udp"                  # UDP scan


class PortState(Enum):
    """Port states enum."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNKNOWN = "unknown"


class PortScannerModule(BaseModule):
    """Port scanner module."""
    
    def __init__(self, **kwargs):
        """Initialize port scanner module."""
        super().__init__(
            name="Port Scanner",
            description="Scans target systems for open ports",
            version="1.0.0",
            **kwargs
        )
        
        # Scanner configuration
        self.timeout = kwargs.get('timeout', 3)
        self.threads = kwargs.get('threads', 50)
        self.scan_type = kwargs.get('scan_type', ScanType.TCP_CONNECT)
        self.ports = kwargs.get('ports', None)  # None means default port range
        self.skip_host_discovery = kwargs.get('skip_host_discovery', False)
        
        # Port ranges
        self.default_ports = [
            20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
        
        # Common service to port mapping
        self.common_ports = {
            'ftp': 21,
            'ssh': 22,
            'telnet': 23,
            'smtp': 25,
            'dns': 53,
            'http': 80,
            'pop3': 110,
            'rpc': 111,
            'msrpc': 135,
            'netbios': 139,
            'imap': 143,
            'https': 443,
            'smb': 445,
            'imaps': 993,
            'pop3s': 995,
            'vpn': 1723,
            'mysql': 3306,
            'rdp': 3389,
            'vnc': 5900,
            'http-alt': 8080,
            'https-alt': 8443
        }
        
        # Known services by port number
        self.services_by_port = {v: k for k, v in self.common_ports.items()}
        
        # Track scan progress
        self.total_ports = 0
        self.scanned_ports = 0
        self.open_ports = {}
        
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Run port scanner on target.
        
        Args:
            target: Target to scan (IP or domain)
            **kwargs: Additional options that can override initial configuration
                - ports: List of ports or port ranges to scan (e.g. [80, 443, "1000-2000"])
                - scan_type: ScanType enum value
                - timeout: Connection timeout in seconds
                - threads: Number of threads to use
                - skip_host_discovery: Skip host discovery phase
        
        Returns:
            Dict with scan results
        """
        # Update configuration from kwargs
        self.timeout = kwargs.get('timeout', self.timeout)
        self.threads = kwargs.get('threads', self.threads)
        self.scan_type = kwargs.get('scan_type', self.scan_type)
        self.ports = kwargs.get('ports', self.ports)
        self.skip_host_discovery = kwargs.get('skip_host_discovery', self.skip_host_discovery)
        
        # Ensure we're running
        self.running = True
        
        scan_results = {
            "target": target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_type": self.scan_type.value if isinstance(self.scan_type, ScanType) else self.scan_type,
            "open_ports": [],
            "filtered_ports": [],
            "closed_ports": []
        }
        
        # Reset tracking variables
        self.open_ports = {}
        self.scanned_ports = 0
        
        self.logger.info(f"Starting port scan on {target}")
        self.update_status(f"Starting port scan on {target}")
        self.update_progress(0)
        
        # Validate target
        if not (is_valid_ip(target) or is_valid_domain(target)):
            self.logger.error(f"Invalid target: {target}")
            return {"error": f"Invalid target: {target}"}
            
        # Resolve hostname to IP if needed
        try:
            ip_address = socket.gethostbyname(target)
            self.logger.info(f"Resolved {target} to {ip_address}")
        except socket.gaierror:
            self.logger.error(f"Could not resolve hostname: {target}")
            return {"error": f"Could not resolve hostname: {target}"}
        
        # Check if host is up if not skipping discovery
        if not self.skip_host_discovery:
            self.update_status("Checking if host is up...")
            if not self._check_host(ip_address):
                self.logger.warning(f"Host {target} ({ip_address}) appears to be down")
                self.update_status("Host appears to be down")
                scan_results["status"] = "down"
                return scan_results
        
        # Determine ports to scan
        ports_to_scan = self._parse_ports(self.ports)
        self.total_ports = len(ports_to_scan)
        
        self.logger.info(f"Scanning {self.total_ports} ports on {target} ({ip_address})")
        self.update_status(f"Scanning {self.total_ports} ports...")
        
        # Execute scan based on scan type
        try:
            if self.scan_type == ScanType.TCP_CONNECT or self.scan_type == "tcp_connect":
                self._tcp_connect_scan(ip_address, ports_to_scan)
            elif self.scan_type == ScanType.TCP_SYN or self.scan_type == "tcp_syn":
                self._tcp_syn_scan(ip_address, ports_to_scan)
            elif self.scan_type == ScanType.UDP or self.scan_type == "udp":
                self._udp_scan(ip_address, ports_to_scan)
            else:
                self.logger.error(f"Unsupported scan type: {self.scan_type}")
                return {"error": f"Unsupported scan type: {self.scan_type}"}
                
            # Process results
            for port, state in self.open_ports.items():
                service = self.services_by_port.get(port, "unknown")
                port_info = {
                    "port": port,
                    "service": service,
                    "state": state.value if isinstance(state, PortState) else state
                }
                
                if state == PortState.OPEN or state == "open":
                    scan_results["open_ports"].append(port_info)
                elif state == PortState.FILTERED or state == "filtered" or state == PortState.OPEN_FILTERED or state == "open|filtered":
                    scan_results["filtered_ports"].append(port_info)
                elif state == PortState.CLOSED or state == "closed":
                    scan_results["closed_ports"].append(port_info)
            
            # Sort results by port number
            scan_results["open_ports"].sort(key=lambda x: x["port"])
            scan_results["filtered_ports"].sort(key=lambda x: x["port"])
            scan_results["closed_ports"].sort(key=lambda x: x["port"])
            
            self.logger.info(f"Scan completed. Found {len(scan_results['open_ports'])} open ports, "
                           f"{len(scan_results['filtered_ports'])} filtered ports.")
            
            self.update_status("Scan completed")
            self.update_progress(100)
            
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Error during port scan: {str(e)}")
            return {"error": f"Error during port scan: {str(e)}"}
            
    def stop(self):
        """Stop the port scanner."""
        self.running = False
        self.logger.info("Port scanner stopped")
        self.update_status("Scan stopped")
    
    def _check_host(self, ip_address: str) -> bool:
        """
        Check if host is up using ICMP echo or TCP ping.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            bool: True if host is up, False otherwise
        """
        # First try TCP ping to port 80
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip_address, 80))
            sock.close()
            if result == 0:
                return True
        except:
            pass
            
        # Then try TCP ping to port 443
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip_address, 443))
            sock.close()
            if result == 0:
                return True
        except:
            pass
            
        # Fall back to a raw socket ping if available (requires root)
        try:
            import ping3
            return ping3.ping(ip_address, timeout=self.timeout) is not None
        except (ImportError, PermissionError):
            pass
            
        # If we couldn't determine, assume it's up
        return True
    
    def _parse_ports(self, ports_spec) -> List[int]:
        """
        Parse port specification into a list of ports.
        
        Args:
            ports_spec: Port specification (can be None, a list of ports, or a list with port ranges as strings)
            
        Returns:
            List of port numbers to scan
        """
        if ports_spec is None:
            return self.default_ports
            
        result = []
        if isinstance(ports_spec, (list, tuple)):
            for item in ports_spec:
                if isinstance(item, int) and is_valid_port(item):
                    result.append(item)
                elif isinstance(item, str) and "-" in item:
                    try:
                        start, end = item.split("-", 1)
                        start_port = int(start.strip())
                        end_port = int(end.strip())
                        if is_valid_port(start_port) and is_valid_port(end_port) and start_port <= end_port:
                            result.extend(range(start_port, end_port + 1))
                    except ValueError:
                        self.logger.warning(f"Invalid port range: {item}")
                else:
                    try:
                        port = int(item)
                        if is_valid_port(port):
                            result.append(port)
                    except (ValueError, TypeError):
                        self.logger.warning(f"Invalid port specification: {item}")
        elif isinstance(ports_spec, str):
            if ports_spec.lower() == "all":
                return list(range(1, 65536))
            elif ports_spec.lower() == "common":
                return self.default_ports
            elif "-" in ports_spec:
                try:
                    start, end = ports_spec.split("-", 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    if is_valid_port(start_port) and is_valid_port(end_port) and start_port <= end_port:
                        return list(range(start_port, end_port + 1))
                except ValueError:
                    self.logger.warning(f"Invalid port range: {ports_spec}")
        
        # If we couldn't parse any ports, use default
        if not result:
            return self.default_ports
            
        return sorted(list(set(result)))  # Remove duplicates and sort
    
    def _tcp_connect_scan(self, ip_address: str, ports: List[int]):
        """
        Perform TCP connect scan.
        
        Args:
            ip_address: IP address to scan
            ports: List of ports to scan
        """
        self.logger.info(f"Starting TCP connect scan on {ip_address} for {len(ports)} ports")
        
        def scan_port(port):
            if not self.running:
                return None
                
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                
                if result == 0:
                    return port, PortState.OPEN
                else:
                    return port, PortState.CLOSED
            except socket.timeout:
                return port, PortState.FILTERED
            except socket.error:
                return port, PortState.FILTERED
            except Exception as e:
                self.logger.debug(f"Error scanning port {port}: {str(e)}")
                return port, PortState.UNKNOWN
            finally:
                self.scanned_ports += 1
                if self.total_ports > 0:
                    progress = int(100 * self.scanned_ports / self.total_ports)
                    self.update_progress(min(progress, 99))  # Cap at 99%
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            
            for future in concurrent.futures.as_completed(futures):
                if not self.running:
                    break
                    
                result = future.result()
                if result:
                    port, state = result
                    if state == PortState.OPEN:
                        self.logger.info(f"Found open port: {port}")
                        self.add_result(f"Open port found: {port}")
                    
                    self.open_ports[port] = state
    
    def _tcp_syn_scan(self, ip_address: str, ports: List[int]):
        """
        Perform TCP SYN scan (requires root privileges).
        
        Args:
            ip_address: IP address to scan
            ports: List of ports to scan
        """
        try:
            # Check if we have required permissions/libraries
            import scapy.all as scapy
        except ImportError:
            self.logger.error("SYN scan requires scapy library. Falling back to TCP connect scan.")
            self.add_result("SYN scan requires scapy library. Falling back to TCP connect scan.")
            self._tcp_connect_scan(ip_address, ports)
            return
            
        self.logger.info(f"Starting TCP SYN scan on {ip_address} for {len(ports)} ports")
        
        # This scan type requires root to create raw sockets, check if we have sufficient privileges
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            test_socket.close()
        except PermissionError:
            self.logger.error("SYN scan requires root privileges. Falling back to TCP connect scan.")
            self.add_result("SYN scan requires root privileges. Falling back to TCP connect scan.")
            self._tcp_connect_scan(ip_address, ports)
            return
        
        # Define packet filtering expression
        src_port = random.randint(1024, 65535)
        
        def scan_port_syn(port):
            if not self.running:
                return None
                
            try:
                # Create SYN packet
                ip_packet = scapy.IP(dst=ip_address)
                syn_packet = ip_packet / scapy.TCP(sport=src_port, dport=port, flags="S")
                
                # Send packet and wait for response
                response = scapy.sr1(syn_packet, timeout=self.timeout, verbose=0)
                
                if response is None:
                    return port, PortState.FILTERED
                elif response.haslayer(scapy.TCP):
                    if response.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
                        # Send RST to close connection
                        rst_packet = ip_packet / scapy.TCP(sport=src_port, dport=port, flags="R")
                        scapy.send(rst_packet, verbose=0)
                        return port, PortState.OPEN
                    elif response.getlayer(scapy.TCP).flags == 0x14:  # RST-ACK
                        return port, PortState.CLOSED
                    else:
                        return port, PortState.FILTERED
                elif response.haslayer(scapy.ICMP):
                    if int(response.getlayer(scapy.ICMP).type) == 3 and int(response.getlayer(scapy.ICMP).code) in [1, 2, 3, 9, 10, 13]:
                        return port, PortState.FILTERED
                
                return port, PortState.UNKNOWN
                
            except Exception as e:
                self.logger.debug(f"Error scanning port {port}: {str(e)}")
                return port, PortState.UNKNOWN
            finally:
                self.scanned_ports += 1
                if self.total_ports > 0:
                    progress = int(100 * self.scanned_ports / self.total_ports)
                    self.update_progress(min(progress, 99))  # Cap at 99%
        
        # SYN scans are faster but we'll still use threading for larger scans
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.threads, 20)) as executor:
            futures = [executor.submit(scan_port_syn, port) for port in ports]
            
            for future in concurrent.futures.as_completed(futures):
                if not self.running:
                    break
                    
                result = future.result()
                if result:
                    port, state = result
                    if state == PortState.OPEN:
                        self.logger.info(f"Found open port: {port}")
                        self.add_result(f"Open port found: {port}")
                    
                    self.open_ports[port] = state
    
    def _udp_scan(self, ip_address: str, ports: List[int]):
        """
        Perform UDP scan. UDP scans are less reliable and slower than TCP scans.
        
        Args:
            ip_address: IP address to scan
            ports: List of ports to scan
        """
        self.logger.info(f"Starting UDP scan on {ip_address} for {len(ports)} ports")
        
        # Define UDP payloads for common services to elicit a response
        # This improves accuracy of UDP scanning
        udp_payloads = {
            53: b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DNS query
            161: b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP
            123: b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # NTP
            137: b'\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01',  # NetBIOS
            1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',  # SSDP
        }
        
        def scan_port_udp(port):
            if not self.running:
                return None
                
            try:
                # Create UDP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Send appropriate payload if available, or empty payload
                payload = udp_payloads.get(port, b'')
                sock.sendto(payload, (ip_address, port))
                
                # Try to receive data
                try:
                    data, _ = sock.recvfrom(1024)
                    sock.close()
                    return port, PortState.OPEN
                except socket.timeout:
                    # No response - could be open or filtered
                    sock.close()
                    return port, PortState.OPEN_FILTERED
                except ConnectionRefusedError:
                    # ICMP port unreachable - port is closed
                    sock.close()
                    return port, PortState.CLOSED
            except Exception as e:
                self.logger.debug(f"Error scanning UDP port {port}: {str(e)}")
                return port, PortState.UNKNOWN
            finally:
                self.scanned_ports += 1
                if self.total_ports > 0:
                    progress = int(100 * self.scanned_ports / self.total_ports)
                    self.update_progress(min(progress, 99))  # Cap at 99%
        
        # UDP scans are much slower, reduce concurrency to avoid overwhelming the network
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.threads, 10)) as executor:
            futures = [executor.submit(scan_port_udp, port) for port in ports]
            
            for future in concurrent.futures.as_completed(futures):
                if not self.running:
                    break
                    
                result = future.result()
                if result:
                    port, state = result
                    if state == PortState.OPEN:
                        self.logger.info(f"Found open UDP port: {port}")
                        self.add_result(f"Open UDP port found: {port}")
                    
                    self.open_ports[port] = state 