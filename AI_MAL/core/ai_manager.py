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
    def __init__(self, model: str = 'artifish/llama3.2-uncensored', fallback_model: str = 'gemma:1b'):
        """Initialize the AI Manager with specified or default model."""
        self.model = model if model else 'artifish/llama3.2-uncensored'
        self.fallback_model = fallback_model if fallback_model else 'gemma:1b'
        self.active_model = None
        self.ollama_url = os.getenv('OLLAMA_API_URL', 'http://localhost:11434')
        self.backup_models = ['artifish/llama3.2-uncensored', 'gemma:1b']
        
        # Track available models
        self.available_models = []

    async def list_available_models(self) -> List[str]:
        """List all available models in Ollama"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.ollama_url}/api/tags") as response:
                    if response.status != 200:
                        logger.warning(f"Failed to list Ollama models: {response.status}")
                        return []
                    
                    data = await response.json()
                    models = [model["name"] for model in data.get("models", [])]
                    model_names = []
                    
                    # Store both the original name and lowercase name for comparison purposes
                    for model in models:
                        model_names.append(model)
                        
                    self.available_models = model_names
                    logger.info(f"Available models: {', '.join(model_names[:5])}{'...' if len(model_names) > 5 else ''}")
                    return model_names
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
            logger.info(f"Requesting AI analysis using model: {self.model}")
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
        available_models_lower = [m.lower() for m in available_models]
        logger.debug(f"Available models: {available_models}")
        
        # Primary model attempt
        try:
            # Check using case-insensitive comparison
            is_available = self.model in available_models or self.model.lower() in available_models_lower
            
            if is_available:
                logger.info(f"Trying primary model: {self.model}")
                
                # Find the actual model name with correct case
                actual_model_name = self.model
                if self.model not in available_models:
                    idx = available_models_lower.index(self.model.lower())
                    actual_model_name = available_models[idx]
                    logger.info(f"Using case-corrected model name: {actual_model_name}")
                
                result = await self._try_model(actual_model_name, prompt)
                if result:
                    return result, actual_model_name
                logger.warning(f"Primary model {self.model} failed to provide analysis")
            else:
                logger.warning(f"Primary model {self.model} not available in Ollama")
                logger.info(f"Available models: {', '.join(available_models[:5])}{'...' if len(available_models) > 5 else ''}")
        except Exception as e:
            logger.warning(f"Error with primary model: {str(e)}")
        
        # Fallback model attempt
        try:
            # Check using case-insensitive comparison
            is_available = (self.fallback_model and 
                           (self.fallback_model in available_models or 
                            self.fallback_model.lower() in available_models_lower))
            
            if is_available:
                logger.info(f"Trying fallback model: {self.fallback_model}")
                
                # Find the actual model name with correct case
                actual_model_name = self.fallback_model
                if self.fallback_model not in available_models:
                    idx = available_models_lower.index(self.fallback_model.lower())
                    actual_model_name = available_models[idx]
                    logger.info(f"Using case-corrected model name: {actual_model_name}")
                
                result = await self._try_model(actual_model_name, prompt)
                if result:
                    return result, actual_model_name
                logger.warning(f"Fallback model {self.fallback_model} failed to provide analysis")
            else:
                if not self.fallback_model:
                    logger.warning("No fallback model configured")
                else:
                    logger.warning(f"Fallback model {self.fallback_model} not available in Ollama")
        except Exception as e:
            logger.warning(f"Error with fallback model: {str(e)}")
        
        # Backup models attempt
        for backup_model in self.backup_models:
            try:
                # Check using case-insensitive comparison
                is_available = backup_model in available_models or backup_model.lower() in available_models_lower
                
                if is_available:
                    logger.info(f"Trying backup model: {backup_model}")
                    
                    # Find the actual model name with correct case
                    actual_model_name = backup_model
                    if backup_model not in available_models:
                        idx = available_models_lower.index(backup_model.lower())
                        actual_model_name = available_models[idx]
                        logger.info(f"Using case-corrected model name: {actual_model_name}")
                    
                    result = await self._try_model(actual_model_name, prompt)
                    if result:
                        return result, actual_model_name
                    logger.warning(f"Backup model {backup_model} failed to provide analysis")
                else:
                    logger.debug(f"Backup model {backup_model} not available in Ollama")
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
                    f"{self.ollama_url}/api/generate",
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

    def _format_assessment_rich(self, assessment: Dict[str, Any]) -> str:
        """Format assessment results into a rich table"""
        try:
            from rich.table import Table
            from rich.box import Box
            from rich.console import Console
            
            # Create a custom box style with divisions between rows
            custom_box = Box(
                "┏━━┳━━┓",  # top
                "┃  ┃  ┃",  # head
                "┣━━╋━━┫",  # head_row
                "┃  ┃  ┃",  # mid
                "┣━━┻━━┫",  # row
                "┃     ┃",  # mid_section
                "┣━━━━━┫",  # section
                "┃     ┃",  # bottom
                "┗━━━━━┛",  # bottom_section
            )
            
            table = Table(
                title=None,
                show_header=True,
                header_style="bold",
                box=custom_box,
                expand=True,
                show_lines=True,
                highlight=True,
                padding=(1, 2)
            )
            
            table.add_column("Category", style="bold cyan")
            table.add_column("Details", style="white")
            
            # Add assessment data
            table.add_row("Risk Level", assessment.get('risk_level', 'UNKNOWN'))
            
            table.add_row("")  # Add empty row for spacing
            
            table.add_row("Summary", assessment.get('summary', 'No summary available'))
            
            table.add_row("")  # Add empty row for spacing
            
            # Format vulnerabilities list
            vulnerabilities = assessment.get('vulnerabilities', [])
            if vulnerabilities:
                vuln_text = ""
                for vuln in vulnerabilities[:5]:
                    vuln_text += f"• {vuln}\n"
                if len(vulnerabilities) > 5:
                    vuln_text += f"• (+{len(vulnerabilities) - 5} more)"
                table.add_row("Vulnerabilities", vuln_text)
            else:
                table.add_row("Vulnerabilities", "None detected")
            
            table.add_row("")  # Add empty row for spacing
            
            # Format attack vectors list
            attack_vectors = assessment.get('attack_vectors', [])
            if attack_vectors:
                vector_text = ""
                for vector in attack_vectors:
                    vector_text += f"• {vector}\n"
                table.add_row("Attack Vectors", vector_text)
            else:
                table.add_row("Attack Vectors", "None identified")
            
            table.add_row("")  # Add empty row for spacing
            
            # Format recommendations list
            recommendations = assessment.get('recommendations', [])
            if recommendations:
                rec_text = ""
                for rec in recommendations:
                    rec_text += f"• {rec}\n"
                table.add_row("Recommendations", rec_text)
            else:
                table.add_row("Recommendations", "No specific recommendations")
            
            # Render table to string
            console = Console(width=80)
            with console.capture() as capture:
                console.print(table)
            return capture.get()
            
        except ImportError:
            # Fallback to plain text if rich is not available
            return self._format_assessment_text(assessment)

    def _format_assessment_text(self, assessment: Dict[str, Any]) -> str:
        """Format assessment results into plain text with dividers"""
        text = "┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
        text += "┃ Category        ┃ Details                                                 ┃\n"
        text += "┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩\n"
        
        # Risk Level
        risk_level = assessment.get("risk_level", "UNKNOWN")
        text += f"│ Risk Level      │ {risk_level}{' ' * (54 - len(risk_level))}│\n"
        
        # Add divider
        text += "├─────────────────┼─────────────────────────────────────────────────────────┤\n"
        
        # Summary 
        summary = assessment.get("summary", "No summary available")
        # Split summary into multiple lines if needed
        summary_lines = self._wrap_text(summary, 54)
        text += f"│ Summary         │ {summary_lines[0]}{' ' * (54 - len(summary_lines[0]))}│\n"
        for line in summary_lines[1:]:
            text += f"│                 │ {line}{' ' * (54 - len(line))}│\n"
        
        # Add divider
        text += "├─────────────────┼─────────────────────────────────────────────────────────┤\n"
        
        # Vulnerabilities
        vulns = assessment.get("vulnerabilities", [])
        if vulns:
            text += f"│ Vulnerabilities │ • {vulns[0]}{' ' * (54 - len('• ' + vulns[0]))}│\n"
            for vuln in vulns[1:5]:
                text += f"│                 │ • {vuln}{' ' * (54 - len('• ' + vuln))}│\n"
            if len(vulns) > 5:
                more_text = f"• (+{len(vulns) - 5} more)"
                text += f"│                 │ {more_text}{' ' * (54 - len(more_text))}│\n"
        else:
            text += "│ Vulnerabilities │ None detected                                       │\n"
        
        # Add divider
        text += "├─────────────────┼─────────────────────────────────────────────────────────┤\n"
        
        # Attack Vectors
        vectors = assessment.get("attack_vectors", [])
        if vectors:
            text += f"│ Attack Vectors  │ • {vectors[0]}{' ' * (54 - len('• ' + vectors[0]))}│\n"
            for vector in vectors[1:]:
                text += f"│                 │ • {vector}{' ' * (54 - len('• ' + vector))}│\n"
        else:
            text += "│ Attack Vectors  │ None identified                                     │\n"
        
        # Add divider
        text += "├─────────────────┼─────────────────────────────────────────────────────────┤\n"
        
        # Recommendations
        recs = assessment.get("recommendations", [])
        if recs:
            text += f"│ Recommendations │ • {recs[0]}{' ' * (54 - len('• ' + recs[0]))}│\n"
            for rec in recs[1:]:
                text += f"│                 │ • {rec}{' ' * (54 - len('• ' + rec))}│\n"
        else:
            text += "│ Recommendations │ No specific recommendations                         │\n"
        
        text += "└─────────────────┴─────────────────────────────────────────────────────────┘\n"
        
        return text
    
    def _wrap_text(self, text: str, width: int) -> List[str]:
        """Wrap text to specified width"""
        if len(text) <= width:
            return [text]
            
        lines = []
        current_line = ""
        for word in text.split():
            if len(current_line) + len(word) + 1 <= width:
                if current_line:
                    current_line += " " + word
                else:
                    current_line = word
            else:
                lines.append(current_line)
                current_line = word
                
        if current_line:
            lines.append(current_line)
            
        return lines

    async def _query_ollama(self, prompt: str, model: str) -> str:
        """
        Query the Ollama API
        """
        try:
            logger.info(f"Querying Ollama API with model: {model}")
            
            # Build request payload
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "num_predict": 2048,
                }
            }
            
            max_retries = 3
            retry_count = 0
            backoff_time = 2  # seconds
            
            while retry_count < max_retries:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(self.ollama_url, json=payload, timeout=60) as response:
                            if response.status == 200:
                                result = await response.json()
                                return result.get('response', '')
                            else:
                                error_text = await response.text()
                                logger.warning(f"Ollama API returned status {response.status}: {error_text}")
                                if retry_count + 1 < max_retries:
                                    retry_count += 1
                                    logger.info(f"Retrying in {backoff_time} seconds (attempt {retry_count}/{max_retries})...")
                                    await asyncio.sleep(backoff_time)
                                    backoff_time *= 2  # Exponential backoff
                                else:
                                    logger.error(f"Failed to query Ollama API after {max_retries} attempts")
                                    raise Exception(f"Ollama API error: {response.status} - {error_text}")
                except aiohttp.ClientError as client_error:
                    if retry_count + 1 < max_retries:
                        retry_count += 1
                        logger.warning(f"Connection error: {str(client_error)}. Retrying ({retry_count}/{max_retries})...")
                        await asyncio.sleep(backoff_time)
                        backoff_time *= 2  # Exponential backoff
                    else:
                        logger.error(f"Connection failed after {max_retries} attempts: {str(client_error)}")
                        raise Exception(f"Connection to Ollama API failed: {str(client_error)}")
            
            # If we get here, we've exhausted retries
            raise Exception(f"Failed to get a valid response from Ollama API after {max_retries} attempts")
            
        except Exception as e:
            logger.error(f"Error querying Ollama API: {str(e)}")
            return f"API Error: {str(e)}" 