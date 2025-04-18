"""
Host Discovery Module.

This module implements network host discovery techniques including:
- ICMP ping sweep
- ARP scanning
- TCP SYN/ACK scanning
- UDP scanning

It can discover hosts on local networks and map network topology.
"""

import socket
import threading
import queue
import time
import ipaddress
import enum
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Set, Union, Optional, Tuple, Any
from dataclasses import dataclass

from src.modules.base import BaseModule
from src.utils.network import (
    is_valid_ip, is_valid_domain, is_valid_ip_range, parse_target,
    get_ip_range, get_hostname_from_ip, ping, get_default_gateway
)


class DiscoveryMethod(enum.Enum):
    """Enum for different host discovery methods."""
    PING = "ping"
    TCP = "tcp"
    UDP = "udp"
    ARP = "arp"
    ALL = "all"


@dataclass
class HostResult:
    """Class for storing host discovery results."""
    ip: str
    status: bool  # True if host is up
    hostname: str = ""
    response_time: float = 0.0
    method: str = ""
    open_ports: List[int] = None


class HostDiscoveryModule(BaseModule):
    """
    Host Discovery Module for network reconnaissance.
    
    Supports multiple discovery techniques including ICMP ping sweep,
    TCP/UDP scanning, and ARP scanning for local networks.
    """
    
    NAME = "host_discovery"
    DESCRIPTION = "Discover active hosts on a network"
    AUTHOR = "Project-N"
    
    def __init__(self):
        super().__init__()
        self.timeout = 2.0
        self.threads = 50
        self.max_hosts = 1024
        self.running = False
        self.results = {}
        self.result_lock = threading.Lock()
        self.host_queue = queue.Queue()
        
        # Ports commonly used for discovery
        self.discovery_ports = [
            22,    # SSH
            23,    # Telnet
            80,    # HTTP
            443,   # HTTPS
            445,   # SMB
            3389,  # RDP
            5060   # SIP
        ]
    
    def run(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run host discovery with provided arguments.
        
        Args:
            args: Dictionary with discovery parameters:
                 - target: IP address, hostname, or CIDR range
                 - method: Discovery method (ping, tcp, udp, arp, all)
                 - timeout: Connection timeout in seconds
                 - threads: Number of concurrent discovery threads
                 - ports: Optional ports for TCP/UDP discovery
                 
        Returns:
            Dictionary with discovery results
        """
        self.running = True
        
        # Set discovery parameters
        target = args.get("target", "")
        method_str = args.get("method", DiscoveryMethod.PING.value)
        self.timeout = float(args.get("timeout", self.timeout))
        self.threads = int(args.get("threads", self.threads))
        ports = args.get("ports", self.discovery_ports)
        
        # Convert ports to list if needed
        if isinstance(ports, str):
            ports = [int(p) for p in ports.split(",") if p.strip().isdigit()]
        
        # Empty previous results
        self.results = {}
        
        # Validate target
        if not target:
            return {"status": "error", "message": "No target specified"}
        
        # Try to auto-detect local network if target is "auto"
        if target.lower() == "auto":
            target = self._detect_local_network()
            if not target:
                return {"status": "error", "message": "Could not auto-detect local network"}
            self.logger.info(f"Auto-detected local network: {target}")
        
        # Determine discovery method
        try:
            method = DiscoveryMethod(method_str)
        except ValueError:
            self.logger.error(f"Unsupported discovery method: {method_str}")
            return {
                "status": "error",
                "message": f"Unsupported discovery method: {method_str}. Use one of: {', '.join([m.value for m in DiscoveryMethod])}"
            }
        
        # Parse target(s) into IP addresses
        targets = self._parse_targets(target)
        if not targets:
            return {"status": "error", "message": f"Invalid target: {target}"}
        
        if len(targets) > self.max_hosts:
            return {"status": "error", "message": f"Too many hosts to scan: {len(targets)}. Maximum is {self.max_hosts}"}
        
        self.logger.info(f"Starting {method.value} discovery on {len(targets)} host(s)")
        
        # Create scan queue
        for ip in targets:
            self.host_queue.put((ip, method))
        
        # Start worker threads
        workers = []
        for _ in range(min(self.threads, self.host_queue.qsize())):
            if not self.running:
                break
                
            thread = threading.Thread(target=self._worker, args=(method, ports))
            thread.daemon = True
            thread.start()
            workers.append(thread)
        
        # Wait for all workers to finish
        self.host_queue.join()
        self.running = False
        
        # Process results
        alive_hosts = [host for host, result in self.results.items() if result.status]
        
        return {
            "status": "success",
            "discovery_method": method.value,
            "targets_scanned": len(targets),
            "hosts_alive": len(alive_hosts),
            "hosts_down": len(targets) - len(alive_hosts),
            "results": {ip: self._host_result_to_dict(result) for ip, result in self.results.items()}
        }
    
    def stop(self) -> None:
        """Stop the running discovery."""
        self.running = False
        with self.host_queue.mutex:
            self.host_queue.queue.clear()
        self.logger.info("Host discovery stopped")
    
    def _worker(self, method: DiscoveryMethod, ports: List[int]) -> None:
        """
        Worker thread for host discovery.
        
        Args:
            method: Discovery method to use
            ports: Ports to use for TCP/UDP discovery
        """
        while self.running:
            try:
                ip, _ = self.host_queue.get(block=False)
            except queue.Empty:
                break
            
            try:
                result = None
                
                # Choose discovery method based on input or use ALL
                if method == DiscoveryMethod.ALL:
                    # Try methods in order of reliability/speed
                    if self._is_local_network(ip):
                        result = self._arp_discovery(ip)
                    
                    if not result or not result.status:
                        result = self._ping_discovery(ip)
                    
                    if not result or not result.status:
                        result = self._tcp_discovery(ip, ports)
                        
                    if not result or not result.status:
                        result = self._udp_discovery(ip, ports)
                        
                elif method == DiscoveryMethod.PING:
                    result = self._ping_discovery(ip)
                    
                elif method == DiscoveryMethod.TCP:
                    result = self._tcp_discovery(ip, ports)
                    
                elif method == DiscoveryMethod.UDP:
                    result = self._udp_discovery(ip, ports)
                    
                elif method == DiscoveryMethod.ARP:
                    if self._is_local_network(ip):
                        result = self._arp_discovery(ip)
                    else:
                        self.logger.warning(f"ARP discovery only works on local networks. Skipping {ip}")
                        result = HostResult(ip=ip, status=False, method="arp")
                
                # Store result if we got one
                if result:
                    with self.result_lock:
                        self.results[ip] = result
                        
                        if result.status:
                            self.logger.info(f"Host {ip} is up ({result.method})" + 
                                           (f", hostname: {result.hostname}" if result.hostname else ""))
            
            except Exception as e:
                self.logger.error(f"Error discovering {ip} - {str(e)}")
                # Add failed result
                with self.result_lock:
                    self.results[ip] = HostResult(ip=ip, status=False)
            
            finally:
                self.host_queue.task_done()
    
    def _detect_local_network(self) -> str:
        """
        Auto-detect the local network for scanning.
        
        Returns:
            CIDR network string or empty string if not detected
        """
        # Try to get default gateway
        gateway = get_default_gateway()
        if not gateway:
            return ""
        
        # Assume a /24 network
        ip_parts = gateway.split('.')
        if len(ip_parts) == 4:
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        
        return ""
    
    def _is_local_network(self, ip: str) -> bool:
        """
        Check if an IP address is on the local network.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP is on local network, False otherwise
        """
        # Get default gateway
        gateway = get_default_gateway()
        if not gateway:
            return False
        
        # Simple heuristic - check if first three octets match
        gateway_parts = gateway.split('.')
        ip_parts = ip.split('.')
        
        if len(gateway_parts) == 4 and len(ip_parts) == 4:
            return (gateway_parts[0] == ip_parts[0] and 
                    gateway_parts[1] == ip_parts[1] and 
                    gateway_parts[2] == ip_parts[2])
        
        return False
    
    def _parse_targets(self, target: str) -> List[str]:
        """
        Parse target string into list of IP addresses.
        
        Args:
            target: Target specification (IP, domain, or CIDR range)
            
        Returns:
            List of IP addresses to discover
        """
        targets = []
        
        # Split multiple targets separated by commas
        for single_target in target.split(","):
            single_target = single_target.strip()
            
            # Check if it's a CIDR range
            if "/" in single_target and not single_target.startswith("http"):
                try:
                    ips = get_ip_range(single_target)
                    targets.extend(ips)
                    continue
                except Exception as e:
                    self.logger.error(f"Invalid CIDR range: {single_target} - {str(e)}")
            
            # Parse as normal target (IP, domain, URL)
            parsed = parse_target(single_target)
            host = parsed['host']
            
            if is_valid_ip(host):
                targets.append(host)
            elif is_valid_domain(host):
                try:
                    ip = socket.gethostbyname(host)
                    targets.append(ip)
                except socket.gaierror:
                    self.logger.error(f"Could not resolve hostname: {host}")
            else:
                self.logger.error(f"Invalid target: {single_target}")
        
        return targets
    
    def _ping_discovery(self, ip: str) -> HostResult:
        """
        Discover host using ICMP ping.
        
        Args:
            ip: IP address to discover
            
        Returns:
            HostResult object with discovery results
        """
        start_time = time.time()
        status = ping(ip, count=1, timeout=int(self.timeout))
        end_time = time.time()
        
        response_time = (end_time - start_time) * 1000 if status else 0
        hostname = get_hostname_from_ip(ip) if status else ""
        
        return HostResult(
            ip=ip,
            status=status,
            hostname=hostname,
            response_time=response_time,
            method="ping",
            open_ports=[]
        )
    
    def _tcp_discovery(self, ip: str, ports: List[int]) -> HostResult:
        """
        Discover host using TCP port scanning.
        
        Args:
            ip: IP address to discover
            ports: Ports to scan
            
        Returns:
            HostResult object with discovery results
        """
        open_ports = []
        status = False
        start_time = time.time()
        
        for port in ports:
            if not self.running:
                break
                
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    status = True
                    break  # One open port is enough to determine host is up
            except:
                pass
        
        end_time = time.time()
        response_time = (end_time - start_time) * 1000 if status else 0
        hostname = get_hostname_from_ip(ip) if status else ""
        
        return HostResult(
            ip=ip,
            status=status,
            hostname=hostname,
            response_time=response_time,
            method="tcp",
            open_ports=open_ports
        )
    
    def _udp_discovery(self, ip: str, ports: List[int]) -> HostResult:
        """
        Discover host using UDP port scanning.
        
        Args:
            ip: IP address to discover
            ports: Ports to scan
            
        Returns:
            HostResult object with discovery results
        """
        open_ports = []
        status = False
        start_time = time.time()
        
        # UDP discovery is less reliable, we'll consider a host up if it
        # responds to any UDP packet with ICMP port unreachable
        for port in ports:
            if not self.running:
                break
                
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Send empty UDP packet
                sock.sendto(b"", (ip, port))
                
                try:
                    data, _ = sock.recvfrom(1024)
                    # If we get data back, port is open
                    open_ports.append(port)
                    status = True
                    break
                except socket.timeout:
                    # Timeout is inconclusive
                    pass
                except ConnectionRefusedError:
                    # ICMP port unreachable, host is up but port closed
                    status = True
                    break
                finally:
                    sock.close()
            except:
                pass
        
        end_time = time.time()
        response_time = (end_time - start_time) * 1000 if status else 0
        hostname = get_hostname_from_ip(ip) if status else ""
        
        return HostResult(
            ip=ip,
            status=status,
            hostname=hostname,
            response_time=response_time,
            method="udp",
            open_ports=open_ports
        )
    
    def _arp_discovery(self, ip: str) -> HostResult:
        """
        Discover host using ARP requests (local network only).
        
        Args:
            ip: IP address to discover
            
        Returns:
            HostResult object with discovery results
        """
        status = False
        mac_address = ""
        start_time = time.time()
        
        try:
            # Try to send an ARP request
            # For Linux systems, we'll use the 'arping' command if available
            if not 'win' in subprocess.sys.platform.lower():
                try:
                    cmd = ['arping', '-c', '1', '-w', str(int(self.timeout)), ip]
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    
                    if process.returncode == 0:
                        status = True
                        # Try to extract MAC address
                        output = stdout.decode('utf-8', errors='ignore')
                        for line in output.splitlines():
                            if "reply from" in line.lower() and ":" in line:
                                mac_parts = line.split("[")[1].split("]")[0]
                                mac_address = mac_parts
                                break
                except (FileNotFoundError, subprocess.SubprocessError):
                    # Fall back to ping if arping is not available
                    status = ping(ip, count=1, timeout=int(self.timeout))
            else:
                # For Windows, fall back to ping
                status = ping(ip, count=1, timeout=int(self.timeout))
        except Exception as e:
            self.logger.debug(f"Error during ARP discovery for {ip}: {str(e)}")
        
        end_time = time.time()
        response_time = (end_time - start_time) * 1000 if status else 0
        hostname = get_hostname_from_ip(ip) if status else ""
        
        return HostResult(
            ip=ip,
            status=status,
            hostname=hostname,
            response_time=response_time,
            method="arp",
            open_ports=[]
        )
    
    def _host_result_to_dict(self, result: HostResult) -> Dict[str, Any]:
        """
        Convert HostResult to dictionary for output.
        
        Args:
            result: HostResult object
            
        Returns:
            Dictionary representation of result
        """
        return {
            "ip": result.ip,
            "status": "up" if result.status else "down",
            "hostname": result.hostname,
            "response_time_ms": round(result.response_time, 2),
            "discovery_method": result.method,
            "open_ports": result.open_ports if result.open_ports else []
        } 