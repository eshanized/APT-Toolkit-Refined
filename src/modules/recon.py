"""
Reconnaissance module for gathering information about a target.
"""
import socket
import time
import ipaddress
import threading
import queue
import whois
import dns.resolver
import subprocess
from typing import Dict, Any, List, Union, Callable, Optional

from src.core.base_module import BaseModule
from src.utils.network import is_valid_ip, is_valid_domain


class ReconModule(BaseModule):
    """
    Module for performing reconnaissance on a target.
    
    This module gathers information about a target including:
    - DNS information
    - Whois information
    - Port scanning
    - Host discovery
    - Service identification
    """
    
    def __init__(self):
        """Initialize the reconnaissance module."""
        super().__init__("recon", "Reconnaissance Module")
        self.timeout = self.get_config("timeout", 30)
        self.dns_servers = self.get_config("dns_servers", ["8.8.8.8", "1.1.1.1"])
        self.whois_timeout = self.get_config("whois_timeout", 10)
        self.port_queue = queue.Queue()
        self.port_results = []
        self.port_scan_complete = False
    
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Run reconnaissance on the target.
        
        Args:
            target: Target to perform reconnaissance on
            **kwargs: Additional arguments
                - ports: Ports to scan (default: common ports)
                - timeout: Timeout in seconds (default: from config)
                - scan_type: Type of scan (default: "basic")
                - threads: Number of threads for port scanning (default: 10)
        
        Returns:
            Dictionary containing reconnaissance results
        """
        self.running = True
        self.status = "running"
        self._update_status("Running reconnaissance...")
        
        # Parse kwargs
        ports = kwargs.get("ports", "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080")
        timeout = kwargs.get("timeout", self.timeout)
        scan_type = kwargs.get("scan_type", "basic")
        threads = kwargs.get("threads", 10)
        
        # Convert ports string to list if needed
        if isinstance(ports, str):
            ports = [int(p) for p in ports.split(",") if p.strip().isdigit()]
        
        # Validate target
        if not target:
            self.logger.error("No target specified")
            self._update_status("Error: No target specified")
            return {"error": "No target specified"}
        
        results = {
            "target": target,
            "timestamp": time.time(),
            "scan_type": scan_type,
            "dns_info": {},
            "whois_info": {},
            "ports": [],
            "hosts": [],
            "services": []
        }
        
        try:
            # Get target type (IP or domain)
            is_ip = is_valid_ip(target)
            is_domain = is_valid_domain(target)
            
            target_type = "ip" if is_ip else "domain" if is_domain else "unknown"
            results["target_type"] = target_type
            
            # Update progress
            self._update_progress(10, "Determining target type...")
            
            # If domain, get DNS info
            if target_type == "domain":
                self._update_status("Getting DNS information...")
                dns_info = self._get_dns_info(target)
                results["dns_info"] = dns_info
                
                # If we have IP addresses from DNS, use the first one for port scanning
                if dns_info.get("a_records"):
                    scan_target = dns_info["a_records"][0]
                else:
                    scan_target = target
            else:
                scan_target = target
            
            # Update progress
            self._update_progress(30, "DNS information retrieved")
            
            # Get whois info
            if target_type in ["domain", "ip"]:
                self._update_status("Getting WHOIS information...")
                whois_info = self._get_whois_info(target)
                results["whois_info"] = whois_info
            
            # Update progress
            self._update_progress(50, "WHOIS information retrieved")
            
            # Perform port scan
            if scan_type in ["basic", "full"]:
                self._update_status("Performing port scan...")
                ports_result = self._scan_ports(scan_target, ports, timeout, threads)
                results["ports"] = ports_result
            
            # Update progress
            self._update_progress(80, "Port scan completed")
            
            # Identify services
            if scan_type in ["full"]:
                self._update_status("Identifying services...")
                services = self._identify_services(scan_target, ports_result)
                results["services"] = services
            
            # Update progress
            self._update_progress(100, "Reconnaissance completed")
            self._update_status("Reconnaissance completed")
            
            # Add result
            self._add_result(results)
            
            return results
        
        except Exception as e:
            self.logger.error(f"Error during reconnaissance: {e}")
            self._update_status(f"Error: {e}")
            return {"error": str(e)}
        
        finally:
            self.running = False
            if self.status != "stopped":
                self.status = "completed"
    
    def _get_dns_info(self, domain: str) -> Dict[str, Any]:
        """
        Get DNS information for a domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            Dictionary containing DNS information
        """
        dns_info = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": []
        }
        
        # Use custom DNS server if specified
        resolver = dns.resolver.Resolver()
        if self.dns_servers:
            resolver.nameservers = self.dns_servers
        
        try:
            # Get A records
            try:
                answers = resolver.resolve(domain, 'A')
                dns_info["a_records"] = [answer.address for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get AAAA records (IPv6)
            try:
                answers = resolver.resolve(domain, 'AAAA')
                dns_info["aaaa_records"] = [answer.address for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get MX records
            try:
                answers = resolver.resolve(domain, 'MX')
                dns_info["mx_records"] = [{
                    "preference": answer.preference, 
                    "exchange": answer.exchange.to_text().rstrip('.')
                } for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get NS records
            try:
                answers = resolver.resolve(domain, 'NS')
                dns_info["ns_records"] = [answer.target.to_text().rstrip('.') for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get TXT records
            try:
                answers = resolver.resolve(domain, 'TXT')
                dns_info["txt_records"] = [answer.to_text().strip('"') for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Get CNAME records
            try:
                answers = resolver.resolve(domain, 'CNAME')
                dns_info["cname_records"] = [answer.target.to_text().rstrip('.') for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
        except Exception as e:
            self.logger.error(f"Error getting DNS info for {domain}: {e}")
        
        return dns_info
    
    def _get_whois_info(self, target: str) -> Dict[str, Any]:
        """
        Get WHOIS information for a target.
        
        Args:
            target: Target to query (domain or IP)
            
        Returns:
            Dictionary containing WHOIS information
        """
        try:
            # Query WHOIS
            whois_info = whois.whois(target)
            
            # Convert to dictionary
            result = {}
            for key, value in whois_info.items():
                # Convert datetime objects to strings
                if isinstance(value, list):
                    result[key] = [str(item) if hasattr(item, 'strftime') else item for item in value]
                elif hasattr(value, 'strftime'):
                    result[key] = str(value)
                else:
                    result[key] = value
            
            return result
        except Exception as e:
            self.logger.error(f"Error getting WHOIS info for {target}: {e}")
            return {"error": str(e)}
    
    def _scan_ports(self, target: str, ports: List[int], timeout: int, threads: int) -> List[Dict[str, Any]]:
        """
        Scan ports on a target.
        
        Args:
            target: Target to scan
            ports: List of ports to scan
            timeout: Timeout in seconds
            threads: Number of threads to use
            
        Returns:
            List of dictionaries containing port information
        """
        self.port_results = []
        self.port_scan_complete = False
        
        # Fill the queue with ports to scan
        for port in ports:
            self.port_queue.put(port)
        
        # Create and start threads
        scan_threads = []
        for _ in range(min(threads, len(ports))):
            thread = threading.Thread(target=self._port_scanner_worker, args=(target, timeout))
            thread.daemon = True
            thread.start()
            scan_threads.append(thread)
        
        # Wait for all threads to complete
        for thread in scan_threads:
            thread.join()
        
        self.port_scan_complete = True
        return self.port_results
    
    def _port_scanner_worker(self, target: str, timeout: int) -> None:
        """
        Worker thread for port scanning.
        
        Args:
            target: Target to scan
            timeout: Timeout in seconds
        """
        while not self.port_scan_complete and not self.port_queue.empty() and self.running:
            try:
                port = self.port_queue.get(False)
                
                # Create socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                # Try to connect
                result = sock.connect_ex((target, port))
                
                # If connection successful
                if result == 0:
                    # Try to get banner
                    banner = self._get_banner(sock)
                    
                    self.port_results.append({
                        "port": port,
                        "state": "open",
                        "banner": banner
                    })
                
                sock.close()
                
            except queue.Empty:
                break
            except socket.error:
                pass
            except Exception as e:
                self.logger.error(f"Error scanning port {port}: {e}")
            
            finally:
                self.port_queue.task_done()
    
    def _get_banner(self, sock: socket.socket) -> str:
        """
        Try to get banner from an open port.
        
        Args:
            sock: Socket connected to the port
            
        Returns:
            Banner string or empty string if no banner
        """
        try:
            # Set a short timeout for banner grabbing
            sock.settimeout(2)
            
            # Send a request that might trigger a response
            sock.send(b"\r\n\r\n")
            
            # Receive data
            banner = sock.recv(1024)
            
            # Convert to string and clean
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            return banner_str
        except:
            return ""
    
    def _identify_services(self, target: str, port_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify services running on open ports.
        
        Args:
            target: Target to scan
            port_results: Results from port scanning
            
        Returns:
            List of dictionaries containing service information
        """
        services = []
        
        # Common port to service mapping
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Proxy"
        }
        
        for port_info in port_results:
            if port_info.get("state") != "open":
                continue
            
            port = port_info.get("port")
            banner = port_info.get("banner", "")
            
            service = {
                "port": port,
                "name": common_services.get(port, "unknown"),
                "banner": banner,
                "version": "unknown"
            }
            
            # Try to identify version from banner
            if banner:
                # Extract version information from banner (simple approach)
                if "SSH" in banner and "OpenSSH" in banner:
                    parts = banner.split()
                    for part in parts:
                        if part.startswith("OpenSSH"):
                            service["version"] = part
                            break
                
                elif "Apache" in banner:
                    parts = banner.split()
                    for i, part in enumerate(parts):
                        if part == "Apache" and i + 1 < len(parts):
                            service["version"] = f"Apache {parts[i+1]}"
                            break
                
                elif "nginx" in banner.lower():
                    parts = banner.split()
                    for part in parts:
                        if part.startswith("nginx/"):
                            service["version"] = part
                            break
            
            services.append(service)
        
        return services
    
    def stop(self) -> None:
        """Stop the reconnaissance module."""
        self.port_scan_complete = True
        super().stop() 