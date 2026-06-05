"""
LLM Integration Module

This module implements the LLM Analysis Layer from Chapter 3, Section 3.2.2.
It constructs prompts and processes vulnerabilities through an LLM to generate
contextual analysis, severity validation, and remediation guidance.
"""

import logging
import time
import os
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from models import Vulnerability, LLMAnalysisResult


logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    """Configuration for LLM API"""
    api_key: str
    model: str = "gpt-4"
    api_base: Optional[str] = None  # For custom API endpoints
    temperature: float = 0.3  # Low temperature for deterministic output
    max_tokens: int = 1000
    top_p: float = 0.9
    timeout: int = 30


class PromptConstructor:
    """
    Constructs context-rich prompts for LLM analysis of vulnerabilities.
    
    Implements the Prompt Construction Module from Chapter 3, Section 3.2.2.
    Uses chain-of-thought prompting and structured output specification
    as described in Chapter 3, Section 3.4.2.
    """
    
    SYSTEM_PROMPT = """You are a senior security engineer conducting a vulnerability analysis. Your task is to assess vulnerabilities identified by automated scanners, validate their severity, and provide clear, actionable remediation guidance to developers.

You should:
1. Analyze the vulnerability with step-by-step reasoning
2. Validate the reported severity based on exploitability and impact
3. Explain the vulnerability in clear terms developers can understand
4. Assess realistic exploitability scenarios
5. Provide specific, actionable remediation steps

Always respond in valid JSON format with the following structure:
{
    "severity_validation": "Confirmed severity with justification",
    "explanation": "Clear explanation of what this vulnerability is and why it matters",
    "exploitability_assessment": "Realistic attack scenarios and exploitability analysis",
    "remediation_steps": ["Step 1", "Step 2", ...],
    "code_example": "Optional corrected code example (if applicable)"
}"""
    
    @staticmethod
    def construct_vulnerability_prompt(vuln: Vulnerability) -> str:
        """
        Construct a comprehensive prompt for LLM analysis of a vulnerability.
        
        Implements the chain-of-thought and contextual enrichment strategies
        from Chapter 3, Section 3.4.2.
        
        Args:
            vuln: Vulnerability object to analyze
            
        Returns:
            Formatted prompt string
        """
        prompt_parts = [
            "# Vulnerability Analysis Request\n",
            f"A security scanner ({vuln.tool}) has identified a potential vulnerability:\n",
            f"\n## Vulnerability Details",
            f"- **ID**: {vuln.vulnerability_id}",
            f"- **Title**: {vuln.title}",
            f"- **Reported Severity**: {vuln.severity.value}",
        ]
        
        if vuln.cvss_score:
            prompt_parts.append(f"- **CVSS Score**: {vuln.cvss_score}")
        
        if vuln.cwe_id:
            prompt_parts.append(f"- **CWE Classification**: {vuln.cwe_id}")
        
        prompt_parts.extend([
            f"- **Affected Component**: {vuln.affected_component}",
            f"- **Description**: {vuln.description}",
        ])
        
        if vuln.file_path:
            prompt_parts.append(f"- **Location**: {vuln.file_path}")
            if vuln.line_number:
                prompt_parts.append(f"  Line: {vuln.line_number}")
        
        if vuln.affected_version:
            prompt_parts.append(f"- **Affected Version**: {vuln.affected_version}")
        
        if vuln.fixed_version:
            prompt_parts.append(f"- **Fixed In**: {vuln.fixed_version}")
        
        if vuln.remediation:
            prompt_parts.append(f"- **Scanner Remediation Advice**: {vuln.remediation}")
        
        prompt_parts.extend([
            "\n## Analysis Tasks",
            "Please perform the following analysis:",
            "",
            "1. **Severity Validation**: Assess whether the reported severity is appropriate. Consider:",
            "   - Exploitability (how easy is it to exploit?)",
            "   - Impact (what damage could an attacker cause?)",
            "   - Context (is this component exposed? does it handle sensitive data?)",
            "",
            "2. **Vulnerability Explanation**: Explain in clear terms:",
            "   - What this vulnerability is",
            "   - Why it exists in this code/dependency",
            "   - What makes it dangerous",
            "",
            "3. **Exploitability Assessment**: Describe:",
            "   - A realistic attack scenario",
            "   - Required attacker capabilities",
            "   - Potential impact on the application",
            "",
            "4. **Remediation Guidance**: Provide:",
            "   - Step-by-step remediation instructions",
            "   - Specific code changes or version upgrades needed",
            "   - Testing recommendations to verify the fix",
            "",
            "Output your analysis in the required JSON format."
        ])
        
        return "\n".join(prompt_parts)
    
    @staticmethod
    def construct_batch_prompt(vulns: List[Vulnerability], max_vulns: int = 5) -> str:
        """
        Construct a prompt for analyzing multiple vulnerabilities.
        
        For efficiency, can batch similar vulnerabilities together.
        
        Args:
            vulns: List of vulnerabilities to analyze
            max_vulns: Maximum vulnerabilities to include in one prompt
            
        Returns:
            Formatted batch prompt
        """
        vulns_subset = vulns[:max_vulns]
        
        prompt_parts = [
            "# Batch Vulnerability Analysis Request\n",
            f"Analyze the following {len(vulns_subset)} vulnerabilities:\n"
        ]
        
        for i, vuln in enumerate(vulns_subset, 1):
            prompt_parts.extend([
                f"\n## Vulnerability {i}",
                f"- **ID**: {vuln.vulnerability_id}",
                f"- **Severity**: {vuln.severity.value}",
                f"- **Component**: {vuln.affected_component}",
                f"- **Description**: {vuln.description[:200]}...",  # Truncate long descriptions
            ])
        
        prompt_parts.extend([
            "\n## Task",
            "For each vulnerability, provide a brief analysis focusing on:",
            "1. Severity validation",
            "2. Key risk factors",
            "3. Primary remediation action",
            "",
            "Respond in JSON array format with one object per vulnerability."
        ])
        
        return "\n".join(prompt_parts)


class LLMAnalyzer:
    """
    Analyzes vulnerabilities using Large Language Models.
    
    Implements the LLM Analysis Layer from Chapter 3, Section 3.2.2.
    """
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.prompt_constructor = PromptConstructor()
        
        # Try to import OpenAI or Anthropic client
        try:
            import openai
            self.client = openai.OpenAI(api_key=config.api_key)
            self.api_type = 'openai'
            logger.info("Using OpenAI API")
        except ImportError:
            logger.error("OpenAI library not installed. Install with: pip install openai")
            raise
    
    def analyze_vulnerability(self, vuln: Vulnerability) -> Optional[LLMAnalysisResult]:
        """
        Analyze a single vulnerability using the LLM.
        
        Args:
            vuln: Vulnerability to analyze
            
        Returns:
            LLMAnalysisResult with analysis, or None if analysis failed
        """
        start_time = time.time()
        
        try:
            # Construct prompt
            user_prompt = self.prompt_constructor.construct_vulnerability_prompt(vuln)
            
            logger.debug(f"Analyzing vulnerability {vuln.vulnerability_id} with LLM")
            
            # Call LLM API
            response = self.client.chat.completions.create(
                model=self.config.model,
                messages=[
                    {"role": "system", "content": PromptConstructor.SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                top_p=self.config.top_p
            )
            
            # Extract response
            response_text = response.choices[0].message.content
            
            # Parse JSON response
            try:
                analysis_data = json.loads(response_text)
            except json.JSONDecodeError:
                # Sometimes LLM wraps JSON in markdown code blocks
                import re
                json_match = re.search(r'```json\s*(\{.*?\})\s*```', response_text, re.DOTALL)
                if json_match:
                    analysis_data = json.loads(json_match.group(1))
                else:
                    logger.error(f"LLM did not return valid JSON: {response_text[:200]}")
                    return None
            
            processing_time = time.time() - start_time
            
            result = LLMAnalysisResult(
                vulnerability_id=vuln.vulnerability_id,
                severity_validation=analysis_data.get('severity_validation', ''),
                explanation=analysis_data.get('explanation', ''),
                exploitability_assessment=analysis_data.get('exploitability_assessment', ''),
                remediation_steps=analysis_data.get('remediation_steps', []),
                code_example=analysis_data.get('code_example'),
                processing_time=processing_time
            )
            
            logger.info(f"Analyzed {vuln.vulnerability_id} in {processing_time:.2f}s")
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerability {vuln.vulnerability_id}: {e}")
            return None
    
    def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        max_concurrent: int = 5
    ) -> Dict[str, LLMAnalysisResult]:
        """
        Analyze multiple vulnerabilities, respecting rate limits.
        
        Args:
            vulnerabilities: List of vulnerabilities to analyze
            max_concurrent: Maximum number of concurrent API calls
            
        Returns:
            Dictionary mapping vulnerability IDs to analysis results
        """
        results = {}
        
        logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities with LLM")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            logger.info(f"Processing vulnerability {i}/{len(vulnerabilities)}: {vuln.vulnerability_id}")
            
            result = self.analyze_vulnerability(vuln)
            
            if result:
                results[vuln.vulnerability_id] = result
            
            # Simple rate limiting: small delay between requests
            if i < len(vulnerabilities):
                time.sleep(0.5)
        
        logger.info(f"Successfully analyzed {len(results)}/{len(vulnerabilities)} vulnerabilities")
        return results
    
    def enhance_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Enhance vulnerabilities with LLM analysis in-place.
        
        Args:
            vulnerabilities: List of vulnerabilities to enhance
            
        Returns:
            Same list with LLM fields populated
        """
        analysis_results = self.analyze_vulnerabilities(vulnerabilities)
        
        for vuln in vulnerabilities:
            if vuln.vulnerability_id in analysis_results:
                result = analysis_results[vuln.vulnerability_id]
                vuln.llm_severity_validation = result.severity_validation
                vuln.llm_explanation = result.explanation
                vuln.llm_exploitability_assessment = result.exploitability_assessment
                vuln.llm_remediation_steps = result.remediation_steps
                vuln.llm_code_example = result.code_example
        
        return vulnerabilities


class MockLLMAnalyzer(LLMAnalyzer):
    """
    Mock LLM analyzer for testing without API calls.
    
    Useful for development and testing when API access is not available.
    """
    
    def __init__(self):
        # Don't call super().__init__() - we don't need real API
        self.prompt_constructor = PromptConstructor()
        self.api_type = 'mock'
        logger.info("Using Mock LLM Analyzer (no API calls)")
    
    def analyze_vulnerability(self, vuln: Vulnerability) -> Optional[LLMAnalysisResult]:
        """Generate mock analysis result"""
        import time
        time.sleep(0.1)  # Simulate API latency
        
        result = LLMAnalysisResult(
            vulnerability_id=vuln.vulnerability_id,
            severity_validation=f"Confirmed {vuln.severity.value} severity based on {vuln.vulnerability_type}",
            explanation=f"This vulnerability in {vuln.affected_component} could allow an attacker to exploit {vuln.vulnerability_type}. The issue arises from {vuln.description[:100]}...",
            exploitability_assessment=f"An attacker with network access could exploit this vulnerability to compromise {vuln.affected_component}. Exploitation complexity: MODERATE.",
            remediation_steps=[
                f"Upgrade {vuln.affected_component} to version {vuln.fixed_version or 'latest'}",
                "Test the application thoroughly after upgrade",
                "Review code for similar vulnerable patterns"
            ],
            code_example=None,
            processing_time=0.1
        )
        
        return result
