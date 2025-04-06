"""AI Model Manager for handling Ollama model interactions."""

import os
import json
import logging
from typing import Optional, Dict, Any, List
import aiohttp
from dotenv import load_dotenv
import asyncio
import subprocess
from pathlib import Path

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class AIManager:
    """Manages interactions with Ollama AI models."""
    
    def __init__(self, model: str = 'qwen2.5-coder:7b', fallback_model: str = 'mistral:7b'):
        """Initialize the AI Manager.
        
        Args:
            model: Name of the Ollama model to use. If None, uses default from env.
            fallback_model: Name of the fallback Ollama model to use if the primary fails.
        """
        self.model = model
        self.fallback_model = fallback_model
        self.base_url = 'http://localhost:11434/api/generate'
        self.timeout = 30  # Default timeout for model responses
        
    async def analyze_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan results using the AI model."""
        try:
            # Prepare prompt
            prompt = self._create_analysis_prompt(scan_results)
            
            # Get analysis from model
            analysis = await self._get_model_response(prompt)
            
            # Parse and structure the analysis
            structured_analysis = self._parse_analysis(analysis)
            
            return structured_analysis
            
        except Exception as e:
            logger.error(f"Error during AI analysis: {str(e)}")
            return {}
    
    async def generate_scripts(self, scan_results: Dict[str, Any], script_type: str = 'python') -> Dict[str, str]:
        """Generate custom exploitation scripts based on scan results."""
        try:
            # Prepare prompt for script generation
            prompt = self._create_script_prompt(scan_results, script_type)
            
            # Get script from model
            script = await self._get_model_response(prompt)
            
            # Parse and structure the script
            structured_script = self._parse_script(script, script_type)
            
            return structured_script
            
        except Exception as e:
            logger.error(f"Error generating scripts: {str(e)}")
            return {}
    
    async def _get_model_response(self, prompt: str) -> str:
        """Get response from the AI model with fallback support."""
        try:
            # Try primary model
            response = await self._query_model(self.model, prompt)
            return response
            
        except Exception as e:
            logger.warning(f"Primary model failed: {str(e)}")
            
            if self.fallback_model:
                try:
                    # Try fallback model
                    response = await self._query_model(self.fallback_model, prompt)
                    return response
                    
                except Exception as e:
                    logger.error(f"Fallback model failed: {str(e)}")
                    raise
    
    async def _query_model(self, model: str, prompt: str) -> str:
        """Query the Ollama API for a specific model."""
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.base_url,
                json={
                    'model': model,
                    'prompt': prompt,
                    'stream': False
                }
            ) as response:
                if response.status != 200:
                    raise Exception(f"Model API error: {response.status}")
                
                result = await response.json()
                return result.get('response', '')
    
    def _create_analysis_prompt(self, scan_results: Dict[str, Any]) -> str:
        """Create a prompt for analyzing scan results."""
        return f"""Analyze the following Nmap scan results and provide a detailed security assessment:

{json.dumps(scan_results, indent=2)}

Please provide:
1. Risk level assessment
2. Identified vulnerabilities
3. Potential attack vectors
4. Security recommendations
5. Summary of findings

Format the response in JSON with the following structure:
{{
    "risk_level": "HIGH|MEDIUM|LOW",
    "vulnerabilities": [
        {{
            "type": "vulnerability type",
            "description": "detailed description",
            "severity": "HIGH|MEDIUM|LOW",
            "affected_services": ["service1", "service2"]
        }}
    ],
    "attack_vectors": [
        {{
            "type": "attack type",
            "description": "detailed description",
            "requirements": ["requirement1", "requirement2"],
            "success_probability": "HIGH|MEDIUM|LOW"
        }}
    ],
    "recommendations": [
        "recommendation1",
        "recommendation2"
    ],
    "summary": "overall assessment"
}}"""
    
    def _create_script_prompt(self, scan_results: Dict[str, Any], script_type: str) -> str:
        """Create a prompt for generating exploitation scripts."""
        return f"""Generate a {script_type} exploitation script based on the following Nmap scan results:

{json.dumps(scan_results, indent=2)}

The script should:
1. Target identified vulnerabilities
2. Include proper error handling
3. Follow security best practices
4. Include logging and reporting
5. Be well-documented

Format the response as a complete, executable {script_type} script."""
    
    def _parse_analysis(self, analysis: str) -> Dict[str, Any]:
        """Parse the AI model's analysis response."""
        try:
            # Extract JSON from response
            json_str = analysis[analysis.find('{'):analysis.rfind('}')+1]
            return json.loads(json_str)
        except Exception as e:
            logger.error(f"Error parsing analysis: {str(e)}")
            return {}
    
    def _parse_script(self, script: str, script_type: str) -> Dict[str, str]:
        """Parse the AI model's script response."""
        try:
            # Extract script content
            script_content = script.strip()
            
            # Create filename based on script type
            filename = f"exploit_{script_type}.{script_type}"
            
            return {filename: script_content}
        except Exception as e:
            logger.error(f"Error parsing script: {str(e)}")
            return {}
    
    def _prepare_analysis_prompt(self, scan_results: Dict) -> str:
        """Prepare prompt for scan analysis.
        
        Args:
            scan_results: Results from Nmap scan
            
        Returns:
            Formatted prompt
        """
        return f"""Analyze the following Nmap scan results and provide a detailed security assessment:

{json.dumps(scan_results, indent=2)}

Please provide:
1. Overall risk level (Low, Medium, High, Critical)
2. Summary of findings
3. List of identified vulnerabilities
4. Potential attack vectors
5. Security recommendations

Format the response as JSON with the following structure:
{{
    "risk_level": "string",
    "summary": "string",
    "vulnerabilities": ["string"],
    "attack_vectors": [
        {{
            "type": "string",
            "description": "string",
            "target": "string",
            "module": "string",
            "options": {{}}
        }}
    ],
    "recommendations": ["string"]
}}"""

    def _prepare_script_prompt(self, scan_results: Dict) -> str:
        """Prepare prompt for attack script generation.
        
        Args:
            scan_results: Results from Nmap scan
            
        Returns:
            Formatted prompt
        """
        return f"""Generate a Python script to exploit vulnerabilities found in the following Nmap scan results:

{json.dumps(scan_results, indent=2)}

The script should:
1. Include necessary imports
2. Handle errors gracefully
3. Use appropriate libraries for network operations
4. Include comments explaining the code
5. Follow security best practices

The script should be ready to execute and should not require additional user input."""

    def _prepare_custom_scripts_prompt(self, scan_results: Dict, script_type: str) -> str:
        """Prepare prompt for custom script generation.
        
        Args:
            scan_results: Results from Nmap scan
            script_type: Type of script to generate
            
        Returns:
            Formatted prompt
        """
        return f"""Generate {script_type} scripts to exploit vulnerabilities found in the following Nmap scan results:

{json.dumps(scan_results, indent=2)}

Generate the following scripts:
1. Service enumeration script
2. Vulnerability exploitation script
3. Post-exploitation script
4. Cleanup script

Each script should:
1. Include necessary imports/modules
2. Handle errors gracefully
3. Use appropriate libraries for network operations
4. Include comments explaining the code
5. Follow security best practices

Format the response as JSON with script names as keys and script contents as values."""

    def _format_script(self, script: str) -> str:
        """Format and validate generated script.
        
        Args:
            script: Raw script from model
            
        Returns:
            Formatted script
        """
        # Remove any markdown code block markers
        script = script.replace("```python", "").replace("```", "").strip()
        
        # Add shebang if missing
        if not script.startswith("#!/usr/bin/env python3"):
            script = "#!/usr/bin/env python3\n\n" + script
            
        return script
    
    def _get_default_analysis(self) -> Dict:
        """Get default analysis results.
        
        Returns:
            Default analysis dictionary
        """
        return {
            "risk_level": "Unknown",
            "summary": "Analysis failed",
            "vulnerabilities": [],
            "attack_vectors": [],
            "recommendations": ["Review scan results manually"]
        }
    
    def _get_default_script(self) -> str:
        """Get default attack script.
        
        Returns:
            Default script content
        """
        return """#!/usr/bin/env python3

# Default attack script
# Generated due to error in custom script generation

def main():
    print("Error: Custom script generation failed")
    print("Please review scan results manually")

if __name__ == "__main__":
    main()
""" 