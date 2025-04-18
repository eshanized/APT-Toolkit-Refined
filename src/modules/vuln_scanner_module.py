#!/usr/bin/env python3
"""
Vulnerability Scanner Module - Identifies potential security vulnerabilities in discovered services.

This module provides a wrapper around the vulnerability scanning functionality that integrates with
the module system by inheriting from BaseModule.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from src.core.base_module import BaseModule
from src.utils.network import parse_target, is_valid_ip, is_valid_domain
from src.modules.vulnerability_scanner import VulnerabilityScannerModule, Vulnerability


class VulnScannerModule(BaseModule):
    """
    Vulnerability Scanner Module that integrates with the module system.
    
    This module wraps the VulnerabilityScannerModule to provide a consistent interface
    with other modules in the system.
    """
    
    def __init__(self):
        """Initialize the Vulnerability Scanner Module."""
        super().__init__(name="vuln_scanner", description="Scan for vulnerabilities in network services")
        self.scanner = VulnerabilityScannerModule()
        self.scan_levels = ["basic", "standard", "deep"]
        
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Run the vulnerability scanner against the specified target.
        
        Args:
            target: Target to scan (IP, domain, or CIDR range)
            **kwargs: Additional arguments:
                - service_info: List of service info dictionaries from port scanner
                - scan_level: Scan intensity level (basic, standard, deep)
                
        Returns:
            Dictionary containing scan results
        """
        self.running = True
        self._update_status("running")
        
        # Validate target
        if not target:
            self._update_status("error")
            return {"status": "error", "message": "No target specified"}
            
        if not (is_valid_ip(target) or is_valid_domain(target)):
            self._update_status("error")
            return {"status": "error", "message": f"Invalid target: {target}"}
            
        # Get scan parameters
        service_info = kwargs.get("service_info", [])
        scan_level = kwargs.get("scan_level", "basic")
        
        if scan_level not in self.scan_levels:
            self.logger.warning(f"Invalid scan level: {scan_level}, defaulting to 'basic'")
            scan_level = "basic"
            
        if not service_info:
            self._update_status("error")
            return {"status": "error", "message": "No service information provided for vulnerability scanning"}
            
        # Begin vulnerability scan
        self.logger.info(f"Starting vulnerability scan against {target} with {scan_level} scan level")
        self._update_progress(10, f"Starting vulnerability scan against {target}")
        
        try:
            # Run the vulnerability scanner
            self._update_progress(20, "Analyzing services for vulnerabilities")
            vulnerabilities = self.scanner.run(target, service_info, scan_level)
            
            self._update_progress(80, "Processing scan results")
            
            # Process and format results
            results = self._format_results(target, vulnerabilities)
            
            self._update_progress(100, "Vulnerability scan complete")
            self._update_status("completed")
            
            return {
                "status": "success",
                "target": target,
                "scan_level": scan_level,
                "vulnerabilities": results["vulnerabilities"],
                "summary": results["summary"]
            }
            
        except Exception as e:
            self.logger.error(f"Error during vulnerability scan: {str(e)}")
            self._update_status("error")
            return {
                "status": "error",
                "message": f"Error during vulnerability scan: {str(e)}"
            }
        finally:
            self.running = False
    
    def stop(self) -> None:
        """Stop the vulnerability scanner."""
        self.scanner.stop()
        super().stop()
    
    def _format_results(self, target: str, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """
        Format vulnerability scan results.
        
        Args:
            target: Scanned target
            vulnerabilities: List of vulnerability objects
            
        Returns:
            Formatted results dictionary
        """
        # Convert vulnerabilities to dictionaries
        vuln_dicts = [v.to_dict() for v in vulnerabilities]
        
        # Group vulnerabilities by severity
        severity_count = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        for vuln in vulnerabilities:
            if vuln.severity in severity_count:
                severity_count[vuln.severity] += 1
        
        # Create summary
        summary = {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": severity_count,
            "target": target
        }
        
        # Add result to module results
        self._add_result({
            "target": target,
            "vulnerabilities": vuln_dicts,
            "summary": summary
        })
        
        return {
            "vulnerabilities": vuln_dicts,
            "summary": summary
        }
    
    def add_custom_vulnerability(self, vuln_data: Dict[str, Any]) -> bool:
        """
        Add a custom vulnerability to the database.
        
        Args:
            vuln_data: Vulnerability data dictionary
            
        Returns:
            Boolean indicating success
        """
        return self.scanner.add_custom_vulnerability(vuln_data)
    
    def get_vulnerability_by_id(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """
        Get vulnerability by ID.
        
        Args:
            vuln_id: Vulnerability ID
            
        Returns:
            Vulnerability dictionary or None
        """
        vuln = self.scanner.get_vulnerability_by_id(vuln_id)
        if vuln:
            return vuln.to_dict()
        return None
    
    def export_vulnerabilities(self, format_type: str = "json") -> str:
        """
        Export vulnerabilities to a specific format.
        
        Args:
            format_type: Export format (json, csv, html)
            
        Returns:
            Formatted string of vulnerabilities
        """
        return self.scanner.export_vulnerabilities(format_type) 