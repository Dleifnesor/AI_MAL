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
    def __init__(self, model: str = 'artifish/llama3.2-uncensored', fallback_model: str = 'mistral:7b'):
        # Set default models if empty strings are provided
        self.primary_model = model if model else 'artifish/llama3.2-uncensored'
        self.fallback_model = fallback_model if fallback_model else 'gemma:7b'
        
        # Define backup models to try if both primary and fallback fail
        # These are the default models that should be installed
        self.backup_models = ['artifish/llama3.2-uncensored', 'gemma:7b']
        
        self.ollama_host = os.getenv('OLLAMA_HOST', 'http://localhost:11434')
        logger.info(f"AI Manager initialized with model: {self.primary_model}, fallback model: {self.fallback_model}")
        logger.info(f"Using Ollama host: {self.ollama_host}")
        
        # Track available models
        self.available_models = []

    async def list_available_models(self) -> List[str]:
        """List all available models in Ollama"""
        if self.available_models:
            return self.available_models
            
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.ollama_host}/api/tags") as response:
                    if response.status != 200:
                        logger.warning(f"Failed to list Ollama models: {response.status}")
                        return []
                    
                    data = await response.json()
                    models = [model["name"] for model in data.get("models", [])]
                    self.available_models = models
                    return models
        except Exception as e:
            logger.warning(f"Failed to list Ollama models: {str(e)}")
            return []

    async def analyze_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scan results using AI
        """
        try:
            # Prepare prompt for analysis
            prompt = self._create_analysis_prompt(scan_results)
            
            # Get AI analysis
            logger.info(f"Requesting AI analysis using model: {self.primary_model}")
            analysis, model_used = await self._get_ai_analysis(prompt)
            
            # Parse and structure the analysis
            structured_analysis = self._parse_analysis(analysis)
            
            # Add information about which model was used
            structured_analysis["model_used"] = model_used
            
            return structured_analysis
            
        except Exception as e:
            logger.error(f"Error during AI analysis: {str(e)}")
            # Return fallback analysis instead of raising
            fallback = self._parse_analysis(self._get_fallback_analysis())
            fallback["model_used"] = "fallback"
            return fallback

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

    async def _get_ai_analysis(self, prompt: str) -> tuple[str, str]:
        """
        Get analysis from AI model with extensive fallback mechanisms
        
        Returns:
            Tuple of (analysis_text, model_used)
        """
        # Get list of available models
        available_models = await self.list_available_models()
        logger.debug(f"Available models: {available_models}")
        
        # Primary model attempt
        try:
            if self.primary_model in available_models:
                logger.info(f"Trying primary model: {self.primary_model}")
                result = await self._try_model(self.primary_model, prompt)
                if result:
                    return result, self.primary_model
                logger.warning(f"Primary model {self.primary_model} failed to provide analysis")
            else:
                logger.warning(f"Primary model {self.primary_model} not available in Ollama")
        except Exception as e:
            logger.warning(f"Error with primary model: {str(e)}")
        
        # Fallback model attempt
        try:
            if self.fallback_model and self.fallback_model in available_models:
                logger.info(f"Trying fallback model: {self.fallback_model}")
                result = await self._try_model(self.fallback_model, prompt)
                if result:
                    return result, self.fallback_model
                logger.warning(f"Fallback model {self.fallback_model} failed to provide analysis")
            else:
                logger.warning(f"Fallback model {self.fallback_model} not available in Ollama")
        except Exception as e:
            logger.warning(f"Error with fallback model: {str(e)}")
        
        # Backup models attempt
        for backup_model in self.backup_models:
            try:
                if backup_model in available_models:
                    logger.info(f"Trying backup model: {backup_model}")
                    result = await self._try_model(backup_model, prompt)
                    if result:
                        return result, backup_model
                    logger.warning(f"Backup model {backup_model} failed to provide analysis")
            except Exception as e:
                logger.warning(f"Error with backup model {backup_model}: {str(e)}")
                continue
        
        # If all models fail, return fallback analysis
        logger.error("All AI models failed, using built-in fallback analysis")
        return self._get_fallback_analysis(), "fallback"
        
    async def _try_model(self, model_name: str, prompt: str) -> Optional[str]:
        """Try to get analysis from a specific model"""
        try:
            async with aiohttp.ClientSession() as session:
                response = await session.post(
                    f"{self.ollama_host}/api/generate",
                    json={
                        "model": model_name,
                        "prompt": prompt,
                        "stream": False
                    },
                    timeout=120  # 2 minute timeout
                )
                
                if response.status != 200:
                    error_text = await response.text()
                    logger.warning(f"Model {model_name} returned non-200 status: {response.status}, {error_text}")
                    return None
                    
                result = await response.json()
                return result.get('response')
        except Exception as e:
            logger.warning(f"Error getting analysis from model {model_name}: {str(e)}")
            return None

    def _get_fallback_analysis(self) -> str:
        """
        Generate a fallback analysis when AI models are unavailable
        """
        logger.info("Using built-in fallback analysis due to AI unavailability")
        return """
Risk Level: MEDIUM
Summary: Unable to perform AI analysis. Basic assessment based on scan results only.
Vulnerabilities:
- Potential service exposures on open ports
- Possible outdated software versions
- Default configurations may be in use
Attack Vectors:
- Direct service exploitation
- Brute force authentication attacks
- Known CVE exploitation
Recommendations:
- Manually review scan results
- Implement firewall rules
- Patch systems regularly
- Disable unnecessary services
- Change default credentials
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