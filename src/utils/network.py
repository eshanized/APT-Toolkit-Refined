"""
Network utility functions.

This module provides utility functions for network operations,
including IP address, domain, URL, and port validation.
"""
import socket
import re
import ipaddress
import subprocess
from typing import List, Dict, Any, Union, Optional, Tuple
from urllib.parse import urlparse


def is_valid_ip(ip_address: str) -> bool:
    """
    Check if a string is a valid IPv4 or IPv6 address.
    
    Args:
        ip_address: IP address to validate
        
    Returns:
        bool: True if valid IP address, False otherwise
    """
    # Check for IPv4
    try:
        socket.inet_pton(socket.AF_INET, ip_address)
        return True
    except socket.error:
        pass
    
    # Check for IPv6
    try:
        socket.inet_pton(socket.AF_INET6, ip_address)
        return True
    except socket.error:
        pass
    
    return False


def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain name.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        bool: True if valid domain name, False otherwise
    """
    if not domain:
        return False
    
    # Basic domain validation pattern
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    if re.match(pattern, domain):
        return True
    
    # Special case for localhost
    if domain.lower() == 'localhost':
        return True
    
    return False


def is_valid_url(url: str) -> bool:
    """
    Check if a string is a valid URL.
    
    Args:
        url: URL to validate
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def is_valid_port(port) -> bool:
    """
    Check if a number is a valid port number (1-65535).
    
    Args:
        port: Port number to validate
        
    Returns:
        bool: True if valid port number, False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def is_valid_ip_range(ip_range: str) -> bool:
    """
    Check if a string is a valid IP range (CIDR notation).
    
    Args:
        ip_range: IP range to check (e.g., "192.168.1.0/24")
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False


def get_hostname_from_ip(ip_address: str) -> str:
    """
    Get hostname from IP address using reverse DNS lookup.
    
    Args:
        ip_address: IP address to get hostname for
        
    Returns:
        str: Hostname if found, empty string otherwise
    """
    try:
        if is_valid_ip(ip_address):
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
    except (socket.herror, socket.gaierror):
        pass
    
    return ""


def get_ip_from_hostname(hostname: str) -> str:
    """
    Get IP address from hostname using DNS lookup.
    
    Args:
        hostname: Hostname to get IP address for
        
    Returns:
        str: IP address if found, empty string otherwise
    """
    try:
        if is_valid_domain(hostname):
            return socket.gethostbyname(hostname)
    except socket.gaierror:
        pass
    
    return ""


def expand_ip_range(ip_range: str) -> List[str]:
    """
    Expand an IP range (CIDR notation) to a list of IPs.
    
    Args:
        ip_range: IP range (e.g., "192.168.1.0/24")
        
    Returns:
        List of IP addresses
    """
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def ping(host: str, count: int = 1, timeout: int = 2) -> bool:
    """
    Ping a host to check if it's reachable.
    
    Args:
        host: Host to ping (IP or domain)
        count: Number of packets to send
        timeout: Timeout in seconds
        
    Returns:
        True if host is reachable, False otherwise
    """
    try:
        # Ping command with timeout
        param = '-n' if 'win' in subprocess.sys.platform.lower() else '-c'
        command = ['ping', param, str(count), '-W', str(timeout), host]
        
        # Run the command
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        # Check return code
        return process.returncode == 0
    except Exception:
        return False


def traceroute(host: str, max_hops: int = 30, timeout: int = 2) -> List[Dict[str, Any]]:
    """
    Perform traceroute to a host.
    
    Args:
        host: Host to trace (IP or domain)
        max_hops: Maximum number of hops
        timeout: Timeout in seconds
        
    Returns:
        List of dictionaries with hop information
    """
    try:
        # Check platform
        if 'win' in subprocess.sys.platform.lower():
            command = ['tracert', '-d', '-h', str(max_hops), '-w', str(timeout * 1000), host]
        else:
            command = ['traceroute', '-n', '-m', str(max_hops), '-w', str(timeout), host]
        
        # Run the command
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        # Parse output
        hops = []
        lines = stdout.split('\n')
        for line in lines:
            if not line or 'traceroute' in line.lower() or 'tracing route' in line.lower():
                continue
            
            # Extract hop number and IP
            match = re.search(r'^\s*(\d+)\s+(?:(\d+\.\d+\.\d+\.\d+)|(\*\s*\*\s*\*))', line)
            if match:
                hop_num = int(match.group(1))
                hop_ip = match.group(2) if match.group(2) else None
                
                # Extract RTT if available
                rtts = []
                rtt_matches = re.findall(r'(\d+(?:\.\d+)?)\s*ms', line)
                if rtt_matches:
                    rtts = [float(rtt) for rtt in rtt_matches]
                
                hop = {
                    "hop": hop_num,
                    "ip": hop_ip,
                    "rtt": rtts,
                    "hostname": get_hostname_from_ip(hop_ip) if hop_ip else None
                }
                
                hops.append(hop)
        
        return hops
    except Exception as e:
        return []


def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Get network interfaces on the system.
    
    Returns:
        List of dictionaries with interface information
    """
    interfaces = []
    
    try:
        # Check platform
        if 'win' in subprocess.sys.platform.lower():
            # Windows
            command = ['ipconfig', '/all']
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            # Parse output
            current_interface = None
            for line in stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # New interface
                if line.endswith(':'):
                    if current_interface:
                        interfaces.append(current_interface)
                    current_interface = {"name": line[:-1].strip(), "ip": None, "mac": None}
                
                # IP address
                elif "IPv4 Address" in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match and current_interface:
                        current_interface["ip"] = ip_match.group(1)
                
                # MAC address
                elif "Physical Address" in line:
                    mac_match = re.search(r'([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})', line, re.IGNORECASE)
                    if mac_match and current_interface:
                        current_interface["mac"] = mac_match.group(1)
            
            # Add the last interface
            if current_interface:
                interfaces.append(current_interface)
        
        else:
            # Linux/Unix
            command = ['ifconfig', '-a']
            try:
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()
            except FileNotFoundError:
                # Try ip command if ifconfig is not available
                command = ['ip', 'addr', 'show']
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()
            
            # Parse output
            current_interface = None
            for line in stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # New interface (ifconfig)
                if line[0].isalnum() and ":" in line:
                    if current_interface:
                        interfaces.append(current_interface)
                    name = line.split(":")[0].strip()
                    current_interface = {"name": name, "ip": None, "mac": None}
                
                # IP address
                elif "inet " in line:
                    ip_match = re.search(r'inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match and current_interface:
                        current_interface["ip"] = ip_match.group(1)
                
                # MAC address
                elif "ether" in line or "HWaddr" in line:
                    mac_match = re.search(r'(?:ether|HWaddr) ([0-9a-f]{2}(?::[0-9a-f]{2}){5})', line, re.IGNORECASE)
                    if mac_match and current_interface:
                        current_interface["mac"] = mac_match.group(1)
            
            # Add the last interface
            if current_interface:
                interfaces.append(current_interface)
    
    except Exception as e:
        pass
    
    return interfaces


def get_default_gateway() -> Optional[str]:
    """
    Get the default gateway IP address.
    
    Returns:
        Default gateway IP or None if not found
    """
    try:
        # Check platform
        if 'win' in subprocess.sys.platform.lower():
            # Windows
            command = ['ipconfig', '/all']
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            # Parse output
            for line in stdout.split('\n'):
                line = line.strip()
                if "Default Gateway" in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        return ip_match.group(1)
        
        else:
            # Linux/Unix
            try:
                command = ['ip', 'route', 'show', 'default']
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()
                
                # Parse output
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', stdout)
                if match:
                    return match.group(1)
            except:
                pass
    
    except Exception:
        pass
    
    return None


def parse_target(target: str) -> dict:
    """
    Parse target string into components (protocol, host, port).
    
    Args:
        target: Target string (IP, domain, or URL)
        
    Returns:
        dict: Dictionary with protocol, host, and port
    """
    result = {
        'protocol': '',
        'host': '',
        'port': None
    }
    
    # Check if it's a URL
    if '//' in target or ':' in target and not target.startswith('['):
        try:
            parsed = urlparse(target if '://' in target else f'http://{target}')
            result['protocol'] = parsed.scheme or 'http'
            
            # Handle port in netloc
            host_port = parsed.netloc.split(':')
            if len(host_port) > 1:
                try:
                    result['port'] = int(host_port[1])
                except ValueError:
                    pass
            
            # Handle IPv6 addresses
            if parsed.netloc.startswith('['):
                # Extract IPv6 address within brackets
                ipv6_end = parsed.netloc.find(']')
                if ipv6_end != -1:
                    result['host'] = parsed.netloc[1:ipv6_end]
            else:
                result['host'] = host_port[0]
                
        except Exception:
            # If URL parsing fails, treat as plain host
            result['host'] = target
    else:
        # Handle host:port format
        if ':' in target:
            host_port = target.split(':')
            result['host'] = host_port[0]
            try:
                result['port'] = int(host_port[1])
            except ValueError:
                pass
        else:
            result['host'] = target
    
    # Assign default ports based on protocol if port is missing
    if not result['port'] and result['protocol']:
        if result['protocol'] == 'http':
            result['port'] = 80
        elif result['protocol'] == 'https':
            result['port'] = 443
        elif result['protocol'] == 'ftp':
            result['port'] = 21
        elif result['protocol'] == 'ssh':
            result['port'] = 22
    
    return result


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """
    Check if a port is open on a host.
    
    Args:
        host: Host to check
        port: Port to check
        timeout: Connection timeout in seconds
        
    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def get_ip_range(cidr: str) -> list:
    """
    Get list of IP addresses from CIDR notation.
    
    Args:
        cidr: CIDR notation string (e.g. '192.168.1.0/24')
        
    Returns:
        list: List of IP addresses in range
    """
    try:
        import ipaddress
        return [str(ip) for ip in ipaddress.IPv4Network(cidr, strict=False)]
    except ImportError:
        # Fall back to manual calculation for small subnets
        ip, subnet = cidr.split('/')
        subnet = int(subnet)
        
        if subnet < 16:
            # Too large, don't attempt
            return []
        
        # Convert IP to integer
        ip_int = 0
        for i, octet in enumerate(reversed(ip.split('.'))):
            ip_int += int(octet) * (256 ** i)
        
        # Calculate range
        ip_count = 2 ** (32 - subnet)
        base_ip = (ip_int // ip_count) * ip_count
        
        # Convert back to IP strings
        result = []
        for i in range(ip_count):
            current = base_ip + i
            octets = []
            for j in range(4):
                octets.insert(0, str(current % 256))
                current = current // 256
            result.append('.'.join(octets))
        
        return result
    except Exception:
        return [] 