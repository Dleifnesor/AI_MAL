#!/usr/bin/env python3
"""
AI Manager module for AI_MAL
"""

import asyncio
import json
import logging
import os
from typing import Dict, List, Optional, Any
import aiohttp
from dotenv import load_dotenv
import re

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class AIManager:
    def __init__(self, model: str = 'qwen2.5-coder:7b', fallback_model: str = 'mistral:7b'):
        self.model = model
        self.fallback_model = fallback_model
        self.ollama_host = os.getenv('OLLAMA_HOST', 'http://localhost:11434')
        logger.info(f"AI Manager initialized with model: {self.model}, fallback model: {self.fallback_model}")
        logger.info(f"Using Ollama host: {self.ollama_host}")

    async def analyze_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scan results using AI
        """
        try:
            # Prepare prompt for analysis
            prompt = self._create_analysis_prompt(scan_results)
            
            # Get AI analysis
            logger.info(f"Requesting AI analysis using model: {self.model}")
            analysis = await self._get_ai_analysis(prompt)
            
            # Parse and structure the analysis
            structured_analysis = self._parse_analysis(analysis)
            
            return structured_analysis
            
        except Exception as e:
            logger.error(f"Error during AI analysis: {str(e)}")
            raise

    def _create_analysis_prompt(self, scan_results: Dict[str, Any]) -> str:
        """
        Create a prompt for AI analysis
        """
        prompt = f"""Analyze the following network scan results and provide a detailed security assessment:

Target: {scan_results['scan_info']['target']}
Scan Type: {scan_results['scan_info']['scan_type']}

Hosts Found:
"""
        for host in scan_results['hosts']:
            prompt += f"\nHost: {host['ip']}"
            if host.get('hostname'):
                prompt += f" ({host['hostname']})"
            prompt += f"\nStatus: {host['status']}"
            
            if host.get('ports'):
                prompt += "\nOpen Ports:"
                for port in host['ports']:
                    service_info = port.get('service', 'unknown')
                    version_info = port.get('version', 'unknown')
                    prompt += f"\n- Port {port['port']}: {service_info} ({version_info})"
            
            if host.get('os') and isinstance(host['os'], dict) and host['os'].get('name'):
                prompt += f"\nOS: {host['os']['name']}"
                if host['os'].get('family'):
                    prompt += f" ({host['os']['family']})"

        prompt += """

Please provide the following information in your analysis, ensuring each section begins with the exact heading as shown:

Risk Level: (LOW, MEDIUM, HIGH)
Summary: (Brief overall assessment)
Vulnerabilities:
- (vulnerability 1)
- (vulnerability 2)
Attack Vectors:
- (attack vector 1)
- (attack vector 2)
Recommendations:
- (recommendation 1)
- (recommendation 2)

Format your response clearly using these exact headings.
"""

        return prompt

    async def _get_ai_analysis(self, prompt: str) -> str:
        """
        Get analysis from AI model
        """
        try:
            async with aiohttp.ClientSession() as session:
                # Try primary model first
                try:
                    logger.debug(f"Sending prompt to {self.model}")
                    response = await session.post(
                        f"{self.ollama_host}/api/generate",
                        json={
                            "model": self.model,
                            "prompt": prompt,
                            "stream": False
                        },
                        timeout=120  # 2 minute timeout
                    )
                    
                    if response.status != 200:
                        error_text = await response.text()
                        logger.warning(f"Primary model returned non-200 status: {response.status}, {error_text}")
                        raise Exception(f"API error: {response.status} - {error_text}")
                        
                    result = await response.json()
                    return result['response']
                    
                except Exception as e:
                    logger.warning(f"Primary model failed, trying fallback: {str(e)}")
                    
                    # Try fallback model
                    logger.debug(f"Sending prompt to fallback model {self.fallback_model}")
                    response = await session.post(
                        f"{self.ollama_host}/api/generate",
                        json={
                            "model": self.fallback_model,
                            "prompt": prompt,
                            "stream": False
                        },
                        timeout=120  # 2 minute timeout
                    )
                    
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"Fallback model returned non-200 status: {response.status}, {error_text}")
                        raise Exception(f"API error: {response.status} - {error_text}")
                    
                    result = await response.json()
                    return result['response']
                    
        except Exception as e:
            logger.error(f"Error getting AI analysis: {str(e)}")
            # Return simple fallback response when AI is unavailable
            return """
Risk Level: MEDIUM
Summary: Unable to perform AI analysis. Basic assessment based on scan results only.
Vulnerabilities:
- Potential service exposures on open ports
Attack Vectors:
- Direct service exploitation
Recommendations:
- Manually review scan results
- Implement firewall rules
- Patch systems regularly
"""

    def _parse_analysis(self, analysis: str) -> Dict[str, Any]:
        """
        Parse AI analysis into structured format
        """
        try:
            # Initialize structured analysis
            structured = {
                "risk_level": "UNKNOWN",
                "summary": "",
                "vulnerabilities": [],
                "attack_vectors": [],
                "recommendations": []
            }
            
            # Extract risk level
            risk_match = re.search(r'Risk Level:\s*(LOW|MEDIUM|HIGH)', analysis, re.IGNORECASE)
            if risk_match:
                structured["risk_level"] = risk_match.group(1).upper()
            
            # Extract summary
            summary_match = re.search(r'Summary:\s*(.*?)(?=\n\n|\n[A-Za-z]+:)', analysis, re.DOTALL)
            if summary_match:
                structured["summary"] = summary_match.group(1).strip()
            
            # Extract vulnerabilities
            vuln_section = re.search(r'Vulnerabilities:(.*?)(?=\n\n|\n[A-Za-z]+:)', analysis, re.DOTALL)
            if vuln_section:
                vulns = vuln_section.group(1).strip().split('\n')
                structured["vulnerabilities"] = [v.strip('- ').strip() for v in vulns if v.strip()]
            
            # Extract attack vectors
            attack_section = re.search(r'Attack Vectors:(.*?)(?=\n\n|\n[A-Za-z]+:)', analysis, re.DOTALL)
            if attack_section:
                vectors = attack_section.group(1).strip().split('\n')
                structured["attack_vectors"] = [v.strip('- ').strip() for v in vectors if v.strip()]
            
            # Extract recommendations
            rec_section = re.search(r'Recommendations:(.*?)(?=\n\n|$)', analysis, re.DOTALL)
            if rec_section:
                recs = rec_section.group(1).strip().split('\n')
                structured["recommendations"] = [r.strip('- ').strip() for r in recs if r.strip()]
            
            return structured
            
        except Exception as e:
            logger.error(f"Error parsing analysis: {str(e)}")
            return {
                "risk_level": "ERROR",
                "summary": "Error parsing analysis",
                "vulnerabilities": [],
                "attack_vectors": [],
                "recommendations": []
            } 