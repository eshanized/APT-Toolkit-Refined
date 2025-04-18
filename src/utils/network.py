"""
Network utility functions.
"""
import socket
import re
import ipaddress
import subprocess
from typing import List, Dict, Any, Union, Optional, Tuple


def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IP address.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain name.
    
    Args:
        domain: Domain name to check
        
    Returns:
        True if valid, False otherwise
    """
    # Regular expression for domain validation
    pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    return bool(re.match(pattern, domain, re.IGNORECASE))


def is_valid_url(url: str) -> bool:
    """
    Check if a string is a valid URL.
    
    Args:
        url: URL to check
        
    Returns:
        True if valid, False otherwise
    """
    pattern = r"^(?:http|https)://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9](?::[0-9]{1,5})?(?:/[^/\s]*)?"
    return bool(re.match(pattern, url, re.IGNORECASE))


def is_valid_port(port: int) -> bool:
    """
    Check if a port number is valid.
    
    Args:
        port: Port number to check
        
    Returns:
        True if valid, False otherwise
    """
    return isinstance(port, int) and 1 <= port <= 65535


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


def get_ip_from_hostname(hostname: str) -> Optional[str]:
    """
    Get IP address from hostname.
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        IP address or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def get_hostname_from_ip(ip: str) -> Optional[str]:
    """
    Get hostname from IP address.
    
    Args:
        ip: IP address to resolve
        
    Returns:
        Hostname or None if resolution fails
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


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