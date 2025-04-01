"""AI Model Manager for handling Ollama model interactions."""

import os
import json
import logging
from typing import Optional, Dict, Any
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
    
    def __init__(self, model_name: str = "qwen2.5-coder:7b"):
        """Initialize the AI Manager.
        
        Args:
            model_name: Name of the Ollama model to use. If None, uses default from env.
        """
        self.ollama_host = os.getenv('OLLAMA_HOST', 'http://localhost:11434')
        self.model_name = model_name
        self.fallback_model = "gemma3:1b"  # Fallback model for less powerful systems
        self.timeout = 30  # Default timeout for model responses
        
    async def _make_request(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make an async request to the Ollama API.
        
        Args:
            endpoint: API endpoint
            data: Request data
            
        Returns:
            API response
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(f"{self.ollama_host}/{endpoint}", json=data) as response:
                    return await response.json()
            except Exception as e:
                logger.error(f"Error making request to Ollama: {e}")
                raise
    
    async def analyze_scan_results(self, scan_results: Dict) -> Dict:
        """Analyze scan results using the AI model.
        
        Args:
            scan_results: Results from Nmap scan
            
        Returns:
            Analysis results including risk level, vulnerabilities, and recommendations
        """
        try:
            # Prepare prompt
            prompt = self._prepare_analysis_prompt(scan_results)
            
            # Get analysis from model
            response = await self._get_model_response(prompt)
            
            # Parse and validate response
            analysis = self._parse_analysis_response(response)
            
            return analysis
            
        except Exception as e:
            logger.warning(f"Error analyzing scan results: {e}")
            return self._get_default_analysis()
    
    async def generate_attack_script(self, scan_results: Dict) -> str:
        """Generate an attack script based on scan results.
        
        Args:
            scan_results: Results from Nmap scan
            
        Returns:
            Generated attack script
        """
        try:
            # Prepare prompt
            prompt = self._prepare_script_prompt(scan_results)
            
            # Get script from model
            response = await self._get_model_response(prompt)
            
            # Validate and format script
            script = self._format_script(response)
            
            return script
            
        except Exception as e:
            logger.warning(f"Error generating attack script: {e}")
            return self._get_default_script()
    
    async def generate_custom_scripts(self, scan_results: Dict, script_type: str = "python") -> Dict[str, str]:
        """Generate custom scripts based on scan results.
        
        Args:
            scan_results: Results from Nmap scan
            script_type: Type of script to generate (python, bash, ruby)
            
        Returns:
            Dictionary mapping script names to their contents
        """
        try:
            # Prepare prompt
            prompt = self._prepare_custom_scripts_prompt(scan_results, script_type)
            
            # Get scripts from model
            response = await self._get_model_response(prompt)
            
            # Parse and validate scripts
            scripts = self._parse_scripts_response(response)
            
            return scripts
            
        except Exception as e:
            logger.warning(f"Error generating custom scripts: {e}")
            return {}
    
    async def _get_model_response(self, prompt: str) -> str:
        """Get response from the AI model.
        
        Args:
            prompt: Input prompt for the model
            
        Returns:
            Model response
        """
        try:
            # Try primary model first
            cmd = ["ollama", "run", self.model_name, prompt]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            if process.returncode == 0:
                return stdout.decode()
                
            # If primary model fails, try fallback model
            if self.fallback_model:
                logger.info(f"Primary model failed, trying fallback model: {self.fallback_model}")
                cmd = ["ollama", "run", self.fallback_model, prompt]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
                
                if process.returncode == 0:
                    return stdout.decode()
                    
            raise Exception(f"Model execution failed: {stderr.decode()}")
            
        except asyncio.TimeoutError:
            raise Exception("Model response timed out")
        except Exception as e:
            raise Exception(f"Error getting model response: {e}")
    
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

    def _parse_analysis_response(self, response: str) -> Dict:
        """Parse and validate analysis response.
        
        Args:
            response: Raw response from model
            
        Returns:
            Parsed analysis results
        """
        try:
            # Extract JSON from response
            json_str = response[response.find("{"):response.rfind("}")+1]
            analysis = json.loads(json_str)
            
            # Validate required fields
            required_fields = ["risk_level", "summary", "vulnerabilities", "attack_vectors", "recommendations"]
            for field in required_fields:
                if field not in analysis:
                    raise ValueError(f"Missing required field: {field}")
                    
            return analysis
            
        except Exception as e:
            logger.error(f"Error parsing analysis response: {e}")
            return self._get_default_analysis()
    
    def _parse_scripts_response(self, response: str) -> Dict[str, str]:
        """Parse and validate scripts response.
        
        Args:
            response: Raw response from model
            
        Returns:
            Dictionary of script names and contents
        """
        try:
            # Extract JSON from response
            json_str = response[response.find("{"):response.rfind("}")+1]
            scripts = json.loads(json_str)
            
            # Validate scripts
            required_scripts = ["enumerate", "exploit", "post_exploit", "cleanup"]
            for script in required_scripts:
                if script not in scripts:
                    raise ValueError(f"Missing required script: {script}")
                    
            return scripts
            
        except Exception as e:
            logger.error(f"Error parsing scripts response: {e}")
            return {}
    
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