#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI_MAL AI Analysis Module
=======================

This module handles AI-powered analysis of scan results and vulnerabilities.
"""

import os
import json
import subprocess
import requests
from .logger import LoggerWrapper

class AIAnalyzer:
    """
    AIAnalyzer class for analyzing scan results using AI.
    """
    
    def __init__(self, model="artifish/llama3.2-uncensored", fallback_model="gemma3:1b", 
                 api_url=None, api_key=None, timeout=60):
        """
        Initialize the AI analyzer.
        
        Args:
            model (str): Primary AI model to use
            fallback_model (str): Fallback AI model if primary fails
            api_url (str, optional): URL for API-based models
            api_key (str, optional): API key for API-based models
            timeout (int): Request timeout in seconds
        """
        self.model = model
        self.fallback_model = fallback_model
        self.api_url = api_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.api_key = api_key or os.environ.get("OLLAMA_API_KEY")
        self.timeout = timeout
        self.logger = LoggerWrapper("AIAnalyzer")
        
    def is_ollama_available(self):
        """
        Check if Ollama is available.
        
        Returns:
            bool: True if Ollama is available, False otherwise
        """
        try:
            response = requests.get(f"{self.api_url}/api/tags", timeout=2)
            return response.status_code == 200
        except Exception:
            return False
    
    def get_available_models(self):
        """
        Get available Ollama models.
        
        Returns:
            list: List of available model names
        """
        try:
            response = requests.get(f"{self.api_url}/api/tags", timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                return [model["name"] for model in data.get("models", [])]
            return []
        except Exception as e:
            self.logger.error(f"Error getting available models: {str(e)}")
            return []
    
    def pull_model_if_needed(self, model_name):
        """
        Pull an Ollama model if it's not already available.
        
        Args:
            model_name (str): The model name to pull
        
        Returns:
            bool: True if the model is available (already or after pulling), False otherwise
        """
        try:
            # Check if model is already available
            available_models = self.get_available_models()
            if model_name in available_models:
                return True
            
            # Try to pull the model
            self.logger.info(f"Pulling model {model_name} (this may take a while)")
            
            # Execute the pull command
            process = subprocess.Popen(
                ["ollama", "pull", model_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Monitor the output
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.logger.debug(output.strip())
            
            # Check the result
            return_code = process.poll()
            if return_code == 0:
                self.logger.info(f"Model {model_name} successfully pulled")
                return True
            else:
                stderr = process.stderr.read()
                self.logger.warning(f"Failed to pull model {model_name}: {stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error pulling model {model_name}: {str(e)}")
            return False
    
    def generate_with_ollama(self, prompt, model_name):
        """
        Generate text using Ollama API.
        
        Args:
            prompt (str): The prompt to send to the model
            model_name (str): The model to use
        
        Returns:
            str: Generated text, or None if failed
        """
        try:
            # API request to Ollama
            response = requests.post(
                f"{self.api_url}/api/generate",
                json={
                    "model": model_name,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get("response", "")
            else:
                self.logger.error(f"Error from Ollama API: {response.text}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error generating with Ollama: {str(e)}")
            return None
    
    def analyze_vulnerabilities(self, vulnerabilities, hosts_info=None):
        """
        Analyze vulnerabilities using AI.
        
        Args:
            vulnerabilities (list): List of vulnerability dictionaries
            hosts_info (list, optional): List of host information dictionaries
        
        Returns:
            dict: Analysis results
        """
        # Skip if no vulnerabilities
        if not vulnerabilities:
            return {
                "risk_assessment": "No vulnerabilities found, risk is minimal.",
                "prioritized_vulnerabilities": [],
                "attack_vectors": [],
                "recommendations": ["No specific recommendations as no vulnerabilities were found."]
            }
        
        # Prepare hosts info string for context
        hosts_context = ""
        if hosts_info:
            hosts_list = []
            for host in hosts_info:
                ip = next((addr["addr"] for addr in host["addresses"] if addr["addrtype"] == "ipv4"), "unknown")
                os_name = host["os"][0]["name"] if host["os"] else "unknown"
                services = [f"{p['portid']}/{p['protocol']}: {p['service'].get('name', 'unknown')}" for p in host["ports"] if p["state"] == "open"]
                hosts_list.append(f"IP: {ip}, OS: {os_name}, Services: {', '.join(services)}")
            
            hosts_context = "Host Information:\n" + "\n".join(hosts_list) + "\n\n"
        
        # Prepare vulnerabilities list for the prompt
        vulns_list = []
        for i, vuln in enumerate(vulnerabilities, 1):
            vuln_desc = (
                f"{i}. Name: {vuln.get('name', 'Unknown')}\n"
                f"   Host: {vuln.get('host', 'Unknown')}\n"
                f"   Port: {vuln.get('port', 'Unknown')}\n"
                f"   Severity: {vuln.get('severity', 'Unknown')}\n"
                f"   CVE: {vuln.get('cve', 'N/A')}\n"
                f"   Description: {vuln.get('description', 'No description available')[:300]}...\n"
            )
            vulns_list.append(vuln_desc)
        
        # Build the prompt
        prompt = f"""You are a cybersecurity expert analyzing the results of a penetration test. Based on the following vulnerabilities and host information, provide:
1. A brief risk assessment
2. Vulnerabilities prioritized by severity and potential impact
3. Potential attack vectors or exploitation paths
4. Recommendations for remediation

{hosts_context}
Vulnerabilities:
{"".join(vulns_list)}

Provide your analysis in JSON format with the following structure:
{{
  "risk_assessment": "A brief summary of the overall risk level (1-2 sentences)",
  "prioritized_vulnerabilities": [
    {{
      "id": "Reference to the vulnerability number from the list",
      "name": "Vulnerability name",
      "risk_level": "Critical/High/Medium/Low",
      "justification": "Why this risk level is assigned (1-2 sentences)"
    }}
  ],
  "attack_vectors": [
    "Description of potential attack vector or exploitation path"
  ],
  "recommendations": [
    "Specific recommendation for remediation"
  ]
}}
"""
        
        # First, try to use the primary model
        if self.is_ollama_available():
            self.logger.info(f"Using {self.model} for vulnerability analysis")
            
            # Pull the model if needed
            if not self.pull_model_if_needed(self.model):
                self.logger.warning(f"Failed to pull {self.model}, trying fallback model {self.fallback_model}")
                
                # Try the fallback model
                if not self.pull_model_if_needed(self.fallback_model):
                    # Fallback to default built-in analysis if can't use AI
                    self.logger.warning("No AI models available, using basic analysis")
                    return self.basic_analysis(vulnerabilities)
                
                # Use the fallback model
                model_to_use = self.fallback_model
            else:
                model_to_use = self.model
            
            # Generate analysis
            analysis_text = self.generate_with_ollama(prompt, model_to_use)
            
            if not analysis_text:
                # Fallback to basic analysis
                self.logger.warning("Failed to generate AI analysis, using basic analysis")
                return self.basic_analysis(vulnerabilities)
            
            # Try to parse the JSON response
            try:
                # Find the JSON part of the response
                json_start = analysis_text.find('{')
                json_end = analysis_text.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    json_str = analysis_text[json_start:json_end]
                    analysis = json.loads(json_str)
                    return analysis
                else:
                    # Try to use the whole response as JSON
                    analysis = json.loads(analysis_text)
                    return analysis
                    
            except json.JSONDecodeError as e:
                self.logger.warning(f"Failed to parse AI analysis as JSON: {str(e)}")
                
                # Return the text as a simple analysis
                return {
                    "risk_assessment": "AI model provided analysis but it could not be parsed as JSON.",
                    "ai_analysis_text": analysis_text,
                    "prioritized_vulnerabilities": [],
                    "attack_vectors": [],
                    "recommendations": ["See full AI analysis text for details."]
                }
        else:
            self.logger.warning("Ollama is not available, using basic analysis")
            return self.basic_analysis(vulnerabilities)
    
    def basic_analysis(self, vulnerabilities):
        """
        Perform basic vulnerability analysis without AI.
        
        Args:
            vulnerabilities (list): List of vulnerability dictionaries
        
        Returns:
            dict: Analysis results
        """
        # Set up empty results
        results = {
            "risk_assessment": "",
            "prioritized_vulnerabilities": [],
            "attack_vectors": [],
            "recommendations": []
        }
        
        # Count vulnerabilities by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            
            # Map numeric severities to text
            if isinstance(severity, (int, float)) or severity.replace('.', '', 1).isdigit():
                severity_val = float(severity)
                if severity_val >= 9.0:
                    severity = "Critical"
                elif severity_val >= 7.0:
                    severity = "High"
                elif severity_val >= 4.0:
                    severity = "Medium"
                else:
                    severity = "Low"
            
            # Map text severities (case insensitive)
            elif isinstance(severity, str):
                severity_lower = severity.lower()
                if "critical" in severity_lower:
                    severity = "Critical"
                elif "high" in severity_lower:
                    severity = "High"
                elif "medium" in severity_lower or "moderate" in severity_lower:
                    severity = "Medium"
                elif "low" in severity_lower:
                    severity = "Low"
                else:
                    severity = "Unknown"
            
            severity_counts[severity] += 1
        
        # Generate risk assessment
        if severity_counts["Critical"] > 0:
            results["risk_assessment"] = f"Critical security risk with {severity_counts['Critical']} critical vulnerabilities."
        elif severity_counts["High"] > 0:
            results["risk_assessment"] = f"High security risk with {severity_counts['High']} high-severity vulnerabilities."
        elif severity_counts["Medium"] > 0:
            results["risk_assessment"] = f"Moderate security risk with {severity_counts['Medium']} medium-severity vulnerabilities."
        elif severity_counts["Low"] > 0:
            results["risk_assessment"] = f"Low security risk with {severity_counts['Low']} low-severity vulnerabilities."
        else:
            results["risk_assessment"] = "Minimal security risk with no significant vulnerabilities."
        
        # Prioritize vulnerabilities
        for i, vuln in enumerate(sorted(vulnerabilities, 
                                        key=lambda v: self._get_severity_value(v.get("severity", "Unknown")), 
                                        reverse=True)):
            # Limit to top 10 vulnerabilities
            if i >= 10:
                break
                
            severity = vuln.get("severity", "Unknown")
            
            # Normalize severity for consistent output
            if isinstance(severity, (int, float)) or severity.replace('.', '', 1).isdigit():
                severity_val = float(severity)
                if severity_val >= 9.0:
                    risk_level = "Critical"
                elif severity_val >= 7.0:
                    risk_level = "High"
                elif severity_val >= 4.0:
                    risk_level = "Medium"
                else:
                    risk_level = "Low"
            else:
                severity_lower = str(severity).lower()
                if "critical" in severity_lower:
                    risk_level = "Critical"
                elif "high" in severity_lower:
                    risk_level = "High"
                elif "medium" in severity_lower or "moderate" in severity_lower:
                    risk_level = "Medium"
                elif "low" in severity_lower:
                    risk_level = "Low"
                else:
                    risk_level = "Unknown"
            
            # Add to prioritized list
            results["prioritized_vulnerabilities"].append({
                "id": i + 1,
                "name": vuln.get("name", "Unknown Vulnerability"),
                "risk_level": risk_level,
                "justification": f"Severity: {severity}, affecting {vuln.get('host', 'unknown host')} on port {vuln.get('port', 'unknown')}"
            })
        
        # Basic attack vectors
        has_web_vuln = any("web" in v.get("name", "").lower() or "http" in v.get("port", "").lower() for v in vulnerabilities)
        has_rce_vuln = any("rce" in v.get("name", "").lower() or "remote code" in v.get("description", "").lower() for v in vulnerabilities)
        has_sql_vuln = any("sql" in v.get("name", "").lower() for v in vulnerabilities)
        
        if has_web_vuln:
            results["attack_vectors"].append("Web application vulnerabilities could be exploited to gain unauthorized access")
        if has_rce_vuln:
            results["attack_vectors"].append("Remote code execution vulnerabilities could allow complete system compromise")
        if has_sql_vuln:
            results["attack_vectors"].append("SQL injection vulnerabilities could lead to database compromise and data exfiltration")
        
        # Generic attack vector if none were specified
        if not results["attack_vectors"]:
            results["attack_vectors"].append("Multiple vulnerabilities could be chained together to gain unauthorized access")
        
        # Basic recommendations
        if severity_counts["Critical"] > 0 or severity_counts["High"] > 0:
            results["recommendations"].append("Immediately patch all critical and high-severity vulnerabilities")
        
        if any("outdated" in v.get("description", "").lower() for v in vulnerabilities):
            results["recommendations"].append("Update all outdated software and services to the latest versions")
        
        if any("patch" in v.get("solution", "").lower() for v in vulnerabilities):
            results["recommendations"].append("Apply available security patches for affected services")
        
        if any("cve" in v.get("cve", "").lower() for v in vulnerabilities):
            results["recommendations"].append("Review and prioritize patching of all identified CVEs")
        
        # Add a generic recommendation if none were specified
        if not results["recommendations"]:
            results["recommendations"].append("Implement a regular security update policy to address vulnerabilities")
        
        return results
    
    def _get_severity_value(self, severity):
        """
        Convert severity to a numeric value for sorting.
        
        Args:
            severity: Severity value in various formats
        
        Returns:
            float: Numeric severity value
        """
        if isinstance(severity, (int, float)) or (isinstance(severity, str) and severity.replace('.', '', 1).isdigit()):
            return float(severity)
        
        severity_lower = str(severity).lower()
        if "critical" in severity_lower:
            return 10.0
        elif "high" in severity_lower:
            return 8.0
        elif "medium" in severity_lower or "moderate" in severity_lower:
            return 5.0
        elif "low" in severity_lower:
            return 2.0
        else:
            return 0.0
    
    def analyze_scan_results(self, scan_results):
        """
        Analyze overall scan results.
        
        Args:
            scan_results (dict): Complete scan results
        
        Returns:
            dict: Analysis results
        """
        results = {}
        
        # Analyze hosts
        if "hosts" in scan_results:
            results["hosts_summary"] = self.summarize_hosts(scan_results["hosts"])
        
        # Analyze vulnerabilities if present
        if "vulnerabilities" in scan_results:
            results["vulnerability_analysis"] = self.analyze_vulnerabilities(
                scan_results["vulnerabilities"], 
                scan_results.get("hosts", [])
            )
        
        # Analyze exploitation results if present
        if "exploits" in scan_results:
            results["exploit_analysis"] = self.analyze_exploits(scan_results["exploits"])
        
        # Generate overall summary
        results["overall_summary"] = self.generate_overall_summary(scan_results, results)
        
        return results
    
    def summarize_hosts(self, hosts):
        """
        Summarize host information.
        
        Args:
            hosts (list): List of host information dictionaries
        
        Returns:
            dict: Host summary
        """
        # Count hosts by status
        status_counts = {}
        for host in hosts:
            status = host.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Count open ports
        total_open_ports = 0
        open_port_counts = {}
        for host in hosts:
            for port in host.get("ports", []):
                if port.get("state") == "open":
                    total_open_ports += 1
                    service_name = port.get("service", {}).get("name", "unknown")
                    open_port_counts[service_name] = open_port_counts.get(service_name, 0) + 1
        
        # Get most common OS
        os_counts = {}
        for host in hosts:
            for os in host.get("os", []):
                os_name = os.get("name", "unknown")
                os_counts[os_name] = os_counts.get(os_name, 0) + 1
        
        most_common_os = max(os_counts.items(), key=lambda x: x[1])[0] if os_counts else "unknown"
        
        # Get most common services
        top_services = sorted(open_port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "total_hosts": len(hosts),
            "up_hosts": status_counts.get("up", 0),
            "total_open_ports": total_open_ports,
            "most_common_os": most_common_os,
            "top_services": [{"name": s[0], "count": s[1]} for s in top_services]
        }
    
    def analyze_exploits(self, exploits):
        """
        Analyze exploitation results.
        
        Args:
            exploits (list): List of exploit result dictionaries
        
        Returns:
            dict: Exploit analysis
        """
        # Count exploits by status
        status_counts = {}
        for exploit in exploits:
            status = exploit.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Get successful exploits
        successful_exploits = [exploit for exploit in exploits if exploit.get("status") == "success"]
        
        # Get unique targets successfully exploited
        exploited_targets = set(exploit.get("target", "") for exploit in successful_exploits)
        
        return {
            "total_attempts": len(exploits),
            "successful": status_counts.get("success", 0),
            "failed": status_counts.get("failure", 0),
            "error": status_counts.get("error", 0),
            "exploited_targets": list(exploited_targets),
            "successful_exploits": [
                {
                    "exploit": e.get("exploit", ""),
                    "target": e.get("target", ""),
                    "vulnerability": e.get("vulnerability", {}).get("name", "")
                }
                for e in successful_exploits
            ]
        }
    
    def generate_overall_summary(self, scan_results, analysis_results):
        """
        Generate an overall summary of scan and analysis results.
        
        Args:
            scan_results (dict): Original scan results
            analysis_results (dict): Generated analysis results
        
        Returns:
            dict: Overall summary
        """
        hosts_summary = analysis_results.get("hosts_summary", {})
        vuln_analysis = analysis_results.get("vulnerability_analysis", {})
        exploit_analysis = analysis_results.get("exploit_analysis", {})
        
        # Determine overall security rating
        security_rating = "Good"
        if vuln_analysis.get("risk_assessment", "").lower().startswith("critical"):
            security_rating = "Critical"
        elif vuln_analysis.get("risk_assessment", "").lower().startswith("high"):
            security_rating = "Poor"
        elif vuln_analysis.get("risk_assessment", "").lower().startswith("moderate"):
            security_rating = "Fair"
        
        # Make worse if successful exploits
        if exploit_analysis and exploit_analysis.get("successful", 0) > 0:
            if security_rating == "Good":
                security_rating = "Fair"
            elif security_rating == "Fair":
                security_rating = "Poor"
            elif security_rating == "Poor":
                security_rating = "Critical"
        
        return {
            "security_rating": security_rating,
            "hosts_scanned": hosts_summary.get("total_hosts", 0),
            "vulnerabilities_found": len(scan_results.get("vulnerabilities", [])),
            "exploits_successful": exploit_analysis.get("successful", 0) if exploit_analysis else 0,
            "risk_assessment": vuln_analysis.get("risk_assessment", "No risk assessment available."),
            "key_recommendations": vuln_analysis.get("recommendations", ["No recommendations available."])
        }
    
    def analyze(self, scan_results):
        """
        Analyze scan results using AI.
        
        Args:
            scan_results (dict): Complete scan results
        
        Returns:
            dict: Analysis results
        """
        self.logger.info("Starting AI analysis of scan results")
        
        try:
            analysis_results = self.analyze_scan_results(scan_results)
            self.logger.info("AI analysis completed successfully")
            return analysis_results
            
        except Exception as e:
            self.logger.exception(f"Error during AI analysis: {str(e)}")
            return {
                "error": f"Error during AI analysis: {str(e)}",
                "overall_summary": {
                    "security_rating": "Unknown",
                    "risk_assessment": "Analysis failed due to an error."
                }
            } 