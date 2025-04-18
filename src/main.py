#!/usr/bin/env python3
"""
Project-N: Network Reconnaissance and Vulnerability Assessment Tool

This is the main entry point for the Project-N tool.
It provides a command-line interface to access all the modules.
"""

import sys
import os
import argparse
import logging
import json
from typing import Dict, Any, List

# Add module directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.modules.host_discovery import HostDiscoveryModule
from src.modules.port_scanner import PortScannerModule
from src.modules.service_scanner import ServiceScannerModule
from src.modules.vulnerability_scanner import VulnerabilityScannerModule


# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("project_n.log")
    ]
)

logger = logging.getLogger("Project-N")


def setup_argparse() -> argparse.ArgumentParser:
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Project-N: Network Reconnaissance and Vulnerability Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover hosts on a network
  python main.py discover --target 192.168.1.0/24 --method ping
  
  # Scan ports on a host
  python main.py scan --target 192.168.1.10 --ports 1-1024 --scan-type tcp_connect
  
  # Identify services on a host
  python main.py services --target 192.168.1.10 --ports 22,80,443
  
  # Check for vulnerabilities
  python main.py vulnerabilities --target 192.168.1.10 --scan-level deep
  
  # Full reconnaissance on a target
  python main.py recon --target 192.168.1.10 --ports 1-1024 --scan-level standard
"""
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Host discovery command
    discover_parser = subparsers.add_parser("discover", help="Discover hosts on a network")
    discover_parser.add_argument("--target", required=True, help="Target IP, domain, or CIDR range")
    discover_parser.add_argument("--method", default="ping", choices=["ping", "tcp", "udp", "arp", "all"], 
                              help="Discovery method")
    discover_parser.add_argument("--timeout", type=float, default=2.0, help="Timeout in seconds")
    discover_parser.add_argument("--threads", type=int, default=50, help="Number of threads")
    discover_parser.add_argument("--output", help="Output file for results (JSON)")
    
    # Port scanning command
    scan_parser = subparsers.add_parser("scan", help="Scan ports on a host")
    scan_parser.add_argument("--target", required=True, help="Target IP or domain")
    scan_parser.add_argument("--ports", default="1-1024", help="Ports to scan (e.g., '22,80,443' or '1-1024')")
    scan_parser.add_argument("--scan-type", default="tcp_connect", choices=["tcp_connect", "syn", "udp"], 
                           help="Scan technique")
    scan_parser.add_argument("--timeout", type=float, default=2.0, help="Timeout in seconds")
    scan_parser.add_argument("--threads", type=int, default=50, help="Number of threads")
    scan_parser.add_argument("--output", help="Output file for results (JSON)")
    
    # Service identification command
    service_parser = subparsers.add_parser("services", help="Identify services on a host")
    service_parser.add_argument("--target", required=True, help="Target IP or domain")
    service_parser.add_argument("--ports", default="", help="Ports to scan (e.g., '22,80,443' or '1-1024')")
    service_parser.add_argument("--timeout", type=float, default=3.0, help="Timeout in seconds")
    service_parser.add_argument("--threads", type=int, default=30, help="Number of threads")
    service_parser.add_argument("--aggressive", action="store_true", help="Enable aggressive probing")
    service_parser.add_argument("--output", help="Output file for results (JSON)")
    
    # Vulnerability scanning command
    vuln_parser = subparsers.add_parser("vulnerabilities", help="Check for vulnerabilities")
    vuln_parser.add_argument("--target", required=True, help="Target IP or domain")
    vuln_parser.add_argument("--ports", default="", help="Ports to scan (e.g., '22,80,443' or '1-1024')")
    vuln_parser.add_argument("--scan-level", default="basic", choices=["basic", "standard", "deep"], 
                           help="Scan intensity level")
    vuln_parser.add_argument("--output", help="Output file for results (JSON)")
    
    # Full reconnaissance command
    recon_parser = subparsers.add_parser("recon", help="Full reconnaissance on a target")
    recon_parser.add_argument("--target", required=True, help="Target IP, domain, or CIDR range")
    recon_parser.add_argument("--ports", default="1-1024", help="Ports to scan (e.g., '22,80,443' or '1-1024')")
    recon_parser.add_argument("--scan-type", default="tcp_connect", choices=["tcp_connect", "syn", "udp"], 
                            help="Scan technique")
    recon_parser.add_argument("--scan-level", default="standard", choices=["basic", "standard", "deep"], 
                            help="Vulnerability scan intensity level")
    recon_parser.add_argument("--threads", type=int, default=30, help="Number of threads")
    recon_parser.add_argument("--timeout", type=float, default=2.0, help="Timeout in seconds")
    recon_parser.add_argument("--output", help="Output file for results (JSON)")
    
    return parser


def discover_hosts(args: argparse.Namespace) -> Dict[str, Any]:
    """Run host discovery module."""
    logger.info(f"Starting host discovery on {args.target} using {args.method} method")
    
    discovery_module = HostDiscoveryModule()
    
    # Prepare arguments
    discovery_args = {
        "target": args.target,
        "method": args.method,
        "timeout": args.timeout,
        "threads": args.threads
    }
    
    # Run discovery
    results = discovery_module.run(discovery_args)
    
    # Save results if requested
    if args.output and results["status"] == "success":
        save_results(results, args.output)
    
    # Print summary
    if results["status"] == "success":
        print(f"\nHost Discovery Results:")
        print(f"Targets scanned: {results['targets_scanned']}")
        print(f"Hosts alive: {results['hosts_alive']}")
        print(f"Hosts down: {results['hosts_down']}")
        
        # Print alive hosts
        if results["hosts_alive"] > 0:
            print("\nAlive hosts:")
            for ip, host_data in results["results"].items():
                if host_data["status"] == "up":
                    hostname = f" ({host_data['hostname']})" if host_data["hostname"] else ""
                    print(f"  {ip}{hostname} - {host_data['discovery_method']}")
    else:
        print(f"Error: {results['message']}")
    
    return results


def scan_ports(args: argparse.Namespace) -> Dict[str, Any]:
    """Run port scanner module."""
    logger.info(f"Starting port scan on {args.target} using {args.scan_type} technique")
    
    scanner_module = PortScannerModule()
    
    # Prepare arguments
    scan_args = {
        "target": args.target,
        "ports": args.ports,
        "scan_type": args.scan_type,
        "timeout": args.timeout,
        "threads": args.threads
    }
    
    # Run scan
    results = scanner_module.run(scan_args)
    
    # Save results if requested
    if args.output and results["status"] == "success":
        save_results(results, args.output)
    
    # Print summary
    if results["status"] == "success":
        print(f"\nPort Scan Results:")
        print(f"Targets scanned: {results['targets_scanned']}")
        print(f"Ports scanned: {results['ports_scanned']}")
        
        for ip, target_data in results["results"].items():
            hostname = f" ({target_data['hostname']})" if target_data["hostname"] else ""
            print(f"\nHost: {ip}{hostname}")
            print(f"Open ports: {target_data['open_ports']}")
            
            # Print open ports with service info
            if target_data["open_ports"] > 0:
                print("\nOpen ports:")
                for port_data in target_data["results"]["open"]:
                    service_info = f" - {port_data['service']}" if port_data["service"] else ""
                    print(f"  {port_data['port']}/tcp{service_info}")
    else:
        print(f"Error: {results['message']}")
    
    return results


def identify_services(args: argparse.Namespace) -> Dict[str, Any]:
    """Run service scanner module."""
    logger.info(f"Starting service identification on {args.target}")
    
    service_module = ServiceScannerModule()
    
    # Prepare arguments
    service_args = {
        "target": args.target,
        "ports": args.ports,
        "timeout": args.timeout,
        "threads": args.threads,
        "aggressive": args.aggressive
    }
    
    # Run service scanner
    results = service_module.run(service_args)
    
    # Save results if requested
    if args.output and results["status"] == "success":
        save_results(results, args.output)
    
    # Print summary
    if results["status"] == "success":
        print(f"\nService Identification Results:")
        print(f"Hosts scanned: {results['hosts_scanned']}")
        print(f"Services discovered: {results['services_discovered']}")
        
        for ip, services in results["results"].items():
            print(f"\nHost: {ip}")
            print("Services:")
            
            for port, service_info in services.items():
                service_name = service_info["service"]
                version_info = f" {service_info['product']} {service_info['version']}" if service_info["version"] else ""
                print(f"  {port}/tcp: {service_name}{version_info}")
    else:
        print(f"Error: {results['message']}")
    
    return results


def scan_vulnerabilities(args: argparse.Namespace, service_results: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Run vulnerability scanner module."""
    logger.info(f"Starting vulnerability scan on {args.target} with {args.scan_level} scan level")
    
    # If we don't have service info, run service scanner first
    if not service_results:
        service_module = ServiceScannerModule()
        service_args = {
            "target": args.target,
            "ports": args.ports,
            "timeout": 3.0,
            "threads": 30,
            "aggressive": True
        }
        service_results = service_module.run(service_args)
        
        if service_results["status"] != "success":
            print(f"Error scanning services: {service_results.get('message', 'Unknown error')}")
            return []
    
    # Initialize vulnerability scanner
    vuln_module = VulnerabilityScannerModule()
    
    # Prepare service info for vulnerability scanner
    all_vulnerabilities = []
    
    # Process each host from service scan
    for ip, services in service_results["results"].items():
        service_info = []
        
        # Convert to format needed by vulnerability scanner
        for port, service_data in services.items():
            service_info.append({
                "host": ip,
                "port": int(port),
                "service": service_data["service"],
                "version": service_data["version"],
                "banner": service_data["banner"]
            })
        
        # Run vulnerability scan on this host's services
        vulnerabilities = vuln_module.run(ip, service_info, args.scan_level)
        all_vulnerabilities.extend(vulnerabilities)
    
    # Print results
    if all_vulnerabilities:
        print(f"\nVulnerability Scan Results:")
        print(f"Total vulnerabilities found: {len(all_vulnerabilities)}")
        
        # Group by severity
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        for vuln in all_vulnerabilities:
            severity = vuln.severity
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Print severity counts
        print("\nVulnerabilities by severity:")
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        # Print top vulnerabilities
        critical_high_vulns = [v for v in all_vulnerabilities if v.severity in ["Critical", "High"]]
        if critical_high_vulns:
            print("\nCritical and High vulnerabilities:")
            for vuln in critical_high_vulns:
                print(f"  [{vuln.severity}] {vuln.name}")
                print(f"    Affected: {vuln.affected_service}")
                if vuln.cve_id:
                    print(f"    CVE: {vuln.cve_id}")
                print(f"    CVSS: {vuln.cvss_score}")
    else:
        print("\nNo vulnerabilities found.")
    
    # Save results if requested
    if args.output and all_vulnerabilities:
        vuln_dicts = [v.to_dict() for v in all_vulnerabilities]
        save_results({"vulnerabilities": vuln_dicts}, args.output)
    
    return all_vulnerabilities


def run_recon(args: argparse.Namespace) -> Dict[str, Any]:
    """Run full reconnaissance on a target."""
    logger.info(f"Starting full reconnaissance on {args.target}")
    
    results = {
        "target": args.target,
        "host_discovery": None,
        "port_scan": None,
        "service_identification": None,
        "vulnerability_scan": None
    }
    
    # Step 1: Host Discovery
    print("\n=== Host Discovery ===")
    discovery_args = argparse.Namespace(
        target=args.target,
        method="all",
        timeout=args.timeout,
        threads=args.threads,
        output=None
    )
    discovery_results = discover_hosts(discovery_args)
    results["host_discovery"] = discovery_results
    
    # Continue if hosts were found
    if discovery_results["status"] == "success" and discovery_results["hosts_alive"] > 0:
        alive_hosts = []
        for ip, host_data in discovery_results["results"].items():
            if host_data["status"] == "up":
                alive_hosts.append(ip)
        
        # If we scanned a network, we'll have multiple hosts
        # For simplicity, we'll just take the first alive host for port scanning
        target_ip = alive_hosts[0]
        
        # Step 2: Port Scanning
        print("\n=== Port Scanning ===")
        scan_args = argparse.Namespace(
            target=target_ip,
            ports=args.ports,
            scan_type=args.scan_type,
            timeout=args.timeout,
            threads=args.threads,
            output=None
        )
        port_results = scan_ports(scan_args)
        results["port_scan"] = port_results
        
        # Continue if open ports were found
        if port_results["status"] == "success":
            # Step 3: Service Identification
            print("\n=== Service Identification ===")
            service_args = argparse.Namespace(
                target=target_ip,
                ports=args.ports,
                timeout=args.timeout,
                threads=args.threads,
                aggressive=True,
                output=None
            )
            service_results = identify_services(service_args)
            results["service_identification"] = service_results
            
            # Step 4: Vulnerability Scanning
            print("\n=== Vulnerability Scanning ===")
            vuln_args = argparse.Namespace(
                target=target_ip,
                ports=args.ports,
                scan_level=args.scan_level,
                output=None
            )
            vuln_results = scan_vulnerabilities(vuln_args, service_results)
            
            # Convert vulnerability objects to dicts for JSON serialization
            results["vulnerability_scan"] = [v.to_dict() for v in vuln_results]
    
    # Save full reconnaissance results
    if args.output:
        save_results(results, args.output)
        print(f"\nFull reconnaissance results saved to {args.output}")
    
    return results


def save_results(results: Dict[str, Any], output_file: str) -> None:
    """Save results to a JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving results to {output_file}: {str(e)}")


def main():
    """Main entry point."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return
    
    print("""
██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗   ███╗   ██╗
██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝   ████╗  ██║
██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║      ██╔██╗ ██║
██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║      ██║╚██╗██║
██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║      ██║ ╚████║
╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝      ╚═╝  ╚═══╝
                                                                        
Network Reconnaissance and Vulnerability Assessment Tool
""")
    
    try:
        if args.command == "discover":
            discover_hosts(args)
        elif args.command == "scan":
            scan_ports(args)
        elif args.command == "services":
            identify_services(args)
        elif args.command == "vulnerabilities":
            scan_vulnerabilities(args)
        elif args.command == "recon":
            run_recon(args)
    except KeyboardInterrupt:
        print("\nOperation interrupted by user.")
        logger.info("Operation interrupted by user.")
    except Exception as e:
        print(f"Error: {str(e)}")
        logger.error(f"Error in main execution: {str(e)}", exc_info=True)


if __name__ == "__main__":
    main() 