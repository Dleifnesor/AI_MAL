#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL Report Generator Module
============================

This module handles report generation for the AI_MAL tool.
"""

import os
import json
import time
import xml.dom.minidom
import xml.etree.ElementTree as ET
from datetime import datetime
from .logger import LoggerWrapper

class ReportGenerator:
    """
    ReportGenerator class for generating reports in different formats.
    """
    
    def __init__(self, output_dir="./results", output_format="json"):
        """
        Initialize the report generator.
        
        Args:
            output_dir (str): Directory to save generated reports
            output_format (str): Format of the report (json/xml)
        """
        self.output_dir = output_dir
        self.output_format = output_format
        self.logger = LoggerWrapper("ReportGenerator")
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_filename(self, target):
        """
        Generate a filename for the report.
        
        Args:
            target (str): Target IP or hostname
        
        Returns:
            str: Generated filename
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        target_safe = target.replace("/", "_").replace(":", "_").replace(" ", "_")
        return f"AI_MAL_report_{target_safe}_{timestamp}.{self.output_format}"
    
    def generate_json_report(self, scan_results):
        """
        Generate a JSON report.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            str: Path to the generated report
        """
        # Extract the target from the scan results
        target = scan_results.get("scan_info", {}).get("target", "unknown")
        
        # Generate the filename
        filename = self.generate_filename(target)
        filepath = os.path.join(self.output_dir, filename)
        
        # Add metadata to the report
        report_data = {
            "report_info": {
                "tool": "AI_MAL",
                "version": "1.0.0",
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": target
            },
            "results": scan_results
        }
        
        # Write the report to a file
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"JSON report saved to {filepath}")
        return filepath
    
    def generate_xml_report(self, scan_results):
        """
        Generate an XML report.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            str: Path to the generated report
        """
        # Extract the target from the scan results
        target = scan_results.get("scan_info", {}).get("target", "unknown")
        
        # Generate the filename
        filename = self.generate_filename(target)
        filepath = os.path.join(self.output_dir, filename)
        
        # Create the root element
        root = ET.Element("AI_MAL_report")
        
        # Add report metadata
        report_info = ET.SubElement(root, "report_info")
        ET.SubElement(report_info, "tool").text = "AI_MAL"
        ET.SubElement(report_info, "version").text = "1.0.0"
        ET.SubElement(report_info, "generated_at").text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ET.SubElement(report_info, "target").text = target
        
        # Convert scan results to XML
        results = ET.SubElement(root, "results")
        self._dict_to_xml(results, scan_results)
        
        # Write the report to a file
        xml_str = ET.tostring(root, encoding="unicode")
        pretty_xml = xml.dom.minidom.parseString(xml_str).toprettyxml(indent="  ")
        
        with open(filepath, 'w') as f:
            f.write(pretty_xml)
        
        self.logger.info(f"XML report saved to {filepath}")
        return filepath
    
    def _dict_to_xml(self, parent, d):
        """
        Convert a dictionary to XML elements.
        
        Args:
            parent (ET.Element): Parent XML element
            d (dict/list/str/int/float): Data to convert
        """
        if isinstance(d, dict):
            for key, value in d.items():
                # Convert key to a valid XML tag name
                key = self._sanitize_xml_tag(key)
                
                # Skip if key is empty after sanitization
                if not key:
                    continue
                
                # Create element with the key as tag name
                child = ET.SubElement(parent, key)
                
                # Handle value recursively
                self._dict_to_xml(child, value)
                
        elif isinstance(d, list):
            # For lists, create "item" elements
            for item in d:
                child = ET.SubElement(parent, "item")
                self._dict_to_xml(child, item)
                
        else:
            # For primitive values, set the text of the parent element
            parent.text = str(d)
    
    def _sanitize_xml_tag(self, tag):
        """
        Sanitize a string to be used as an XML tag name.
        
        Args:
            tag (str): The string to sanitize
        
        Returns:
            str: Sanitized XML tag name
        """
        # Convert to string if not already
        tag = str(tag)
        
        # Replace spaces and special characters
        tag = tag.replace(" ", "_").replace("-", "_")
        
        # Remove invalid characters (only allow a-z, A-Z, 0-9, _, .)
        tag = ''.join(c for c in tag if c.isalnum() or c in ['_', '.'])
        
        # XML tag names cannot start with a number or punctuation
        if tag and (tag[0].isdigit() or tag[0] in ['_', '.']):
            tag = 'x' + tag
        
        return tag
    
    def generate_html_report(self, scan_results):
        """
        Generate an HTML report.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            str: Path to the generated report
        """
        # Extract the target from the scan results
        target = scan_results.get("scan_info", {}).get("target", "unknown")
        
        # Generate the filename
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        target_safe = target.replace("/", "_").replace(":", "_").replace(" ", "_")
        filename = f"AI_MAL_report_{target_safe}_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        # HTML template
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI_MAL Report - {target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }}
        header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        table, th, td {{
            border: 1px solid #ddd;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        .severity-critical {{
            background-color: #ffcccc;
        }}
        .severity-high {{
            background-color: #ffddcc;
        }}
        .severity-medium {{
            background-color: #ffffcc;
        }}
        .severity-low {{
            background-color: #e6f2ff;
        }}
        .success {{
            color: #008000;
        }}
        .failure {{
            color: #cc0000;
        }}
        footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 0.9em;
            color: #777;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        .collapsible {{
            background-color: #f2f2f2;
            color: #444;
            cursor: pointer;
            padding: 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 15px;
            margin: 2px 0;
        }}
        .active, .collapsible:hover {{
            background-color: #e6e6e6;
        }}
        .content {{
            padding: 0 18px;
            display: none;
            overflow: hidden;
            background-color: #f9f9f9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AI_MAL Penetration Testing Report</h1>
            <p>Generated at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>Target: {target}</p>
        </header>
        
        <div class="section">
            {self._generate_summary_html(scan_results)}
        </div>
        
        <div class="section">
            {self._generate_hosts_html(scan_results)}
        </div>
        
        <div class="section">
            {self._generate_vulnerabilities_html(scan_results)}
        </div>
        
        <div class="section">
            {self._generate_exploits_html(scan_results)}
        </div>
        
        <div class="section">
            {self._generate_scripts_html(scan_results)}
        </div>
        
        <div class="section">
            {self._generate_ai_analysis_html(scan_results)}
        </div>
        
        <footer>
            <p>Generated by AI_MAL - AI-Powered Penetration Testing Tool</p>
            <p>Version 1.0.0</p>
        </footer>
    </div>
    
    <script>
        // JavaScript for collapsible sections
        var coll = document.getElementsByClassName("collapsible");
        for (var i = 0; i < coll.length; i++) {{
            coll[i].addEventListener("click", function() {{
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.display === "block") {{
                    content.style.display = "none";
                }} else {{
                    content.style.display = "block";
                }}
            }});
        }}
    </script>
</body>
</html>"""
        
        # Write the report to a file
        with open(filepath, 'w') as f:
            f.write(html_template)
        
        self.logger.info(f"HTML report saved to {filepath}")
        return filepath
    
    def _generate_summary_html(self, scan_results):
        """
        Generate HTML for the summary section.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            str: HTML content
        """
        html = "<h2>Executive Summary</h2>"
        
        # Get AI analysis summary if available
        ai_analysis = scan_results.get("ai_analysis", {})
        overall_summary = ai_analysis.get("overall_summary", {})
        
        if overall_summary:
            security_rating = overall_summary.get("security_rating", "Unknown")
            risk_assessment = overall_summary.get("risk_assessment", "No risk assessment available.")
            
            html += f"""
            <table>
                <tr>
                    <th>Security Rating</th>
                    <td>{security_rating}</td>
                </tr>
                <tr>
                    <th>Risk Assessment</th>
                    <td>{risk_assessment}</td>
                </tr>
                <tr>
                    <th>Hosts Scanned</th>
                    <td>{overall_summary.get("hosts_scanned", 0)}</td>
                </tr>
                <tr>
                    <th>Vulnerabilities Found</th>
                    <td>{overall_summary.get("vulnerabilities_found", 0)}</td>
                </tr>
                <tr>
                    <th>Successful Exploits</th>
                    <td>{overall_summary.get("exploits_successful", 0)}</td>
                </tr>
            </table>
            
            <h3>Key Recommendations</h3>
            <ul>
            """
            
            # Add recommendations
            recommendations = overall_summary.get("key_recommendations", ["No recommendations available."])
            for rec in recommendations:
                html += f"<li>{rec}</li>"
            
            html += "</ul>"
        else:
            html += "<p>No summary information available.</p>"
        
        return html
    
    def _generate_hosts_html(self, scan_results):
        """
        Generate HTML for the hosts section.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            str: HTML content
        """
        hosts = scan_results.get("hosts", [])
        
        if not hosts:
            return "<h2>Hosts</h2><p>No host information available.</p>"
        
        html = f"<h2>Hosts ({len(hosts)})</h2>"
        
        for i, host in enumerate(hosts):
            # Get host details
            host_ip = next((addr["addr"] for addr in host.get("addresses", []) if addr.get("addrtype") == "ipv4"), "Unknown")
            status = host.get("status", "Unknown")
            
            # Create a collapsible section for each host
            html += f"""
            <button class="collapsible">{host_ip} - Status: {status}</button>
            <div class="content">
                <table>
                    <tr>
                        <th>IP Address</th>
                        <td>{host_ip}</td>
                    </tr>
                    <tr>
                        <th>Status</th>
                        <td>{status}</td>
                    </tr>
            """
            
            # Add hostnames if available
            hostnames = host.get("hostnames", [])
            if hostnames:
                hostname_list = ", ".join([h.get("name", "") for h in hostnames if h.get("name")])
                if hostname_list:
                    html += f"""
                    <tr>
                        <th>Hostnames</th>
                        <td>{hostname_list}</td>
                    </tr>
                    """
            
            # Add OS info if available
            os_info = host.get("os", [])
            if os_info:
                os_name = os_info[0].get("name", "Unknown") if os_info else "Unknown"
                os_accuracy = os_info[0].get("accuracy", "Unknown") if os_info else "Unknown"
                html += f"""
                <tr>
                    <th>Operating System</th>
                    <td>{os_name} (Accuracy: {os_accuracy})</td>
                </tr>
                """
            
            html += "</table>"
            
            # Add open ports
            open_ports = [port for port in host.get("ports", []) if port.get("state") == "open"]
            if open_ports:
                html += f"""
                <h3>Open Ports ({len(open_ports)})</h3>
                <table>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                """
                
                for port in open_ports:
                    port_id = port.get("portid", "")
                    protocol = port.get("protocol", "")
                    service = port.get("service", {})
                    service_name = service.get("name", "")
                    product = service.get("product", "")
                    version = service.get("version", "")
                    
                    html += f"""
                    <tr>
                        <td>{port_id}</td>
                        <td>{protocol}</td>
                        <td>{service_name}</td>
                        <td>{product} {version}</td>
                    </tr>
                    """
                
                html += "</table>"
            
            html += "</div>"
        
        return html
    
    def _generate_vulnerabilities_html(self, scan_results):
        """
        Generate HTML for the vulnerabilities section.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            str: HTML content
        """
        vulnerabilities = scan_results.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return "<h2>Vulnerabilities</h2><p>No vulnerabilities found.</p>"
        
        html = f"<h2>Vulnerabilities ({len(vulnerabilities)})</h2>"
        
        # Group vulnerabilities by severity
        severity_groups = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "Low": [],
            "Unknown": []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            
            # Normalize severity
            if isinstance(severity, (int, float)) or (isinstance(severity, str) and severity.replace('.', '', 1).isdigit()):
                severity_val = float(severity)
                if severity_val >= 9.0:
                    group = "Critical"
                elif severity_val >= 7.0:
                    group = "High"
                elif severity_val >= 4.0:
                    group = "Medium"
                else:
                    group = "Low"
            else:
                severity_lower = str(severity).lower()
                if "critical" in severity_lower:
                    group = "Critical"
                elif "high" in severity_lower:
                    group = "High"
                elif "medium" in severity_lower or "moderate" in severity_lower:
                    group = "Medium"
                elif "low" in severity_lower:
                    group = "Low"
                else:
                    group = "Unknown"
            
            severity_groups[group].append(vuln)
        
        # Display vulnerabilities by severity
        for severity, vulns in severity_groups.items():
            if not vulns:
                continue
            
            html += f"""
            <button class="collapsible">{severity} Vulnerabilities ({len(vulns)})</button>
            <div class="content">
            """
            
            for vuln in vulns:
                name = vuln.get("name", "Unknown")
                host = vuln.get("host", "")
                port = vuln.get("port", "")
                cve = vuln.get("cve", "N/A")
                description = vuln.get("description", "")
                solution = vuln.get("solution", "")
                
                # Add CSS class based on severity
                severity_class = f"severity-{severity.lower()}"
                
                html += f"""
                <div class="{severity_class}" style="margin-bottom: 20px; padding: 10px; border-radius: 5px;">
                    <h3>{name}</h3>
                    <table>
                        <tr>
                            <th>Target</th>
                            <td>{host}:{port}</td>
                        </tr>
                        <tr>
                            <th>Severity</th>
                            <td>{severity}</td>
                        </tr>
                """
                
                if cve and cve != "N/A":
                    html += f"""
                        <tr>
                            <th>CVE</th>
                            <td>{cve}</td>
                        </tr>
                    """
                
                html += f"""
                        <tr>
                            <th>Description</th>
                            <td>{description}</td>
                        </tr>
                """
                
                if solution:
                    html += f"""
                        <tr>
                            <th>Solution</th>
                            <td>{solution}</td>
                        </tr>
                    """
                
                html += """
                    </table>
                </div>
                """
            
            html += "</div>"
        
        return html
    
    def _generate_exploits_html(self, scan_results):
        """
        Generate HTML for the exploits section.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            str: HTML content
        """
        exploits = scan_results.get("exploits", [])
        
        if not exploits:
            return "<h2>Exploitation Results</h2><p>No exploitation attempts were made.</p>"
        
        # Count successful exploits
        successful = len([e for e in exploits if e.get("status") == "success"])
        failed = len([e for e in exploits if e.get("status") == "failure"])
        
        html = f"""
        <h2>Exploitation Results</h2>
        <table>
            <tr>
                <th>Total Attempts</th>
                <td>{len(exploits)}</td>
            </tr>
            <tr>
                <th>Successful</th>
                <td class="success">{successful}</td>
            </tr>
            <tr>
                <th>Failed</th>
                <td class="failure">{failed}</td>
            </tr>
        </table>
        """
        
        # Display successful exploits
        if successful > 0:
            html += """
            <h3>Successful Exploits</h3>
            <table>
                <tr>
                    <th>Exploit</th>
                    <th>Target</th>
                    <th>Vulnerability</th>
                </tr>
            """
            
            for exploit in exploits:
                if exploit.get("status") == "success":
                    target = exploit.get("target", "")
                    exploit_name = exploit.get("exploit", "")
                    
                    # Get vulnerability info if available
                    vuln_name = ""
                    if "vulnerability" in exploit:
                        vuln = exploit["vulnerability"]
                        vuln_name = vuln.get("name", "")
                    
                    html += f"""
                    <tr>
                        <td>{exploit_name}</td>
                        <td>{target}</td>
                        <td>{vuln_name}</td>
                    </tr>
                    """
            
            html += "</table>"
        
        return html
    
    def _generate_scripts_html(self, scan_results):
        """
        Generate HTML for the scripts section.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            str: HTML content
        """
        scripts = scan_results.get("scripts", [])
        
        if not scripts:
            return "<h2>Generated Scripts</h2><p>No scripts were generated.</p>"
        
        html = f"""
        <h2>Generated Scripts ({len(scripts)})</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Filename</th>
                <th>Target</th>
                <th>Language</th>
            </tr>
        """
        
        for script in scripts:
            script_type = script.get("type", "Exploit")
            if script_type == "enumeration":
                script_type_display = "Enumeration"
            elif script_type == "post-exploitation":
                script_type_display = "Post-Exploitation"
            else:
                script_type_display = "Exploit"
            
            filename = script.get("filename", "")
            target = script.get("target", "")
            language = script.get("script_type", "")
            
            html += f"""
            <tr>
                <td>{script_type_display}</td>
                <td>{filename}</td>
                <td>{target}</td>
                <td>{language}</td>
            </tr>
            """
        
        html += "</table>"
        
        return html
    
    def _generate_ai_analysis_html(self, scan_results):
        """
        Generate HTML for the AI analysis section.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            str: HTML content
        """
        ai_analysis = scan_results.get("ai_analysis", {})
        
        if not ai_analysis:
            return "<h2>AI Analysis</h2><p>No AI analysis was performed.</p>"
        
        html = "<h2>AI Analysis</h2>"
        
        # Display vulnerability analysis
        vuln_analysis = ai_analysis.get("vulnerability_analysis", {})
        if vuln_analysis:
            html += """
            <h3>Vulnerability Analysis</h3>
            """
            
            # Risk assessment
            risk_assessment = vuln_analysis.get("risk_assessment", "")
            if risk_assessment:
                html += f"""
                <p><strong>Risk Assessment:</strong> {risk_assessment}</p>
                """
            
            # Prioritized vulnerabilities
            prioritized_vulns = vuln_analysis.get("prioritized_vulnerabilities", [])
            if prioritized_vulns:
                html += f"""
                <h4>Prioritized Vulnerabilities ({len(prioritized_vulns)})</h4>
                <table>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Risk Level</th>
                        <th>Justification</th>
                    </tr>
                """
                
                for vuln in prioritized_vulns:
                    vuln_id = vuln.get("id", "")
                    name = vuln.get("name", "")
                    risk_level = vuln.get("risk_level", "")
                    justification = vuln.get("justification", "")
                    
                    # Add CSS class based on risk level
                    risk_class = ""
                    if risk_level.lower() == "critical":
                        risk_class = "severity-critical"
                    elif risk_level.lower() == "high":
                        risk_class = "severity-high"
                    elif risk_level.lower() == "medium":
                        risk_class = "severity-medium"
                    elif risk_level.lower() == "low":
                        risk_class = "severity-low"
                    
                    html += f"""
                    <tr class="{risk_class}">
                        <td>{vuln_id}</td>
                        <td>{name}</td>
                        <td>{risk_level}</td>
                        <td>{justification}</td>
                    </tr>
                    """
                
                html += "</table>"
            
            # Attack vectors
            attack_vectors = vuln_analysis.get("attack_vectors", [])
            if attack_vectors:
                html += f"""
                <h4>Potential Attack Vectors</h4>
                <ul>
                """
                
                for vector in attack_vectors:
                    html += f"<li>{vector}</li>"
                
                html += "</ul>"
            
            # Recommendations
            recommendations = vuln_analysis.get("recommendations", [])
            if recommendations:
                html += f"""
                <h4>Recommendations</h4>
                <ul>
                """
                
                for rec in recommendations:
                    html += f"<li>{rec}</li>"
                
                html += "</ul>"
        
        return html
    
    def generate_report(self, scan_results):
        """
        Generate a report in the specified format.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            str: Path to the generated report
        """
        self.logger.info(f"Generating {self.output_format} report")
        
        if self.output_format == "json":
            return self.generate_json_report(scan_results)
        elif self.output_format == "xml":
            return self.generate_xml_report(scan_results)
        elif self.output_format == "html":
            return self.generate_html_report(scan_results)
        else:
            self.logger.warning(f"Unsupported output format: {self.output_format}, defaulting to JSON")
            return self.generate_json_report(scan_results) 