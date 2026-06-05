"""
Vulnerability Data Models

This module defines the unified data structures for representing vulnerabilities
detected by multiple scanning tools, as specified in Chapter 3, Section 3.2.2.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime
import json


class Severity(Enum):
    """Standardized severity levels across all scanning tools"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
    UNKNOWN = "Unknown"

    @classmethod
    def from_string(cls, severity_str: str) -> 'Severity':
        """Convert various severity string formats to standardized Severity enum"""
        severity_map = {
            'critical': cls.CRITICAL,
            'high': cls.HIGH,
            'medium': cls.MEDIUM,
            'moderate': cls.MEDIUM,  # Some tools use "moderate"
            'low': cls.LOW,
            'info': cls.INFO,
            'informational': cls.INFO,
            'unknown': cls.UNKNOWN,
            'negligible': cls.LOW,  # Trivy uses this
        }
        return severity_map.get(severity_str.lower(), cls.UNKNOWN)

    @classmethod
    def from_cvss(cls, cvss_score: float) -> 'Severity':
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return cls.CRITICAL
        elif cvss_score >= 7.0:
            return cls.HIGH
        elif cvss_score >= 4.0:
            return cls.MEDIUM
        elif cvss_score > 0.0:
            return cls.LOW
        else:
            return cls.UNKNOWN


@dataclass
class VulnerabilityReference:
    """External references for a vulnerability (CVE, CWE, advisories)"""
    type: str  # "CVE", "CWE", "GHSA", "URL"
    id: str
    url: Optional[str] = None


@dataclass
class Vulnerability:
    """
    Unified vulnerability representation across all scanning tools.
    
    This data model implements the normalized vulnerability structure described
    in Chapter 3, Section 3.2.2 (Normalization Module).
    """
    # Core identification
    tool: str  # Scanner that detected this vulnerability
    vulnerability_id: str  # CVE, CWE, or tool-specific ID
    title: str
    description: str
    
    # Severity assessment
    severity: Severity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    
    # Location information
    affected_component: str = ""  # Package name, file path, etc.
    affected_version: str = ""
    fixed_version: str = ""
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    
    # Classification
    vulnerability_type: str = ""  # CWE category, vulnerability class
    cwe_id: Optional[str] = None
    
    # Additional metadata
    references: List[VulnerabilityReference] = field(default_factory=list)
    remediation: str = ""  # Original tool's remediation advice
    exploitability: Optional[str] = None
    published_date: Optional[str] = None
    
    # LLM enhancement fields (populated by LLM analysis)
    llm_severity_validation: Optional[str] = None
    llm_explanation: Optional[str] = None
    llm_exploitability_assessment: Optional[str] = None
    llm_remediation_steps: Optional[List[str]] = None
    llm_code_example: Optional[str] = None
    
    # Metadata
    scan_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    raw_data: Dict[str, Any] = field(default_factory=dict)  # Original tool output
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary for JSON serialization"""
        return {
            'tool': self.tool,
            'vulnerability_id': self.vulnerability_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'affected_component': self.affected_component,
            'affected_version': self.affected_version,
            'fixed_version': self.fixed_version,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'vulnerability_type': self.vulnerability_type,
            'cwe_id': self.cwe_id,
            'references': [{'type': r.type, 'id': r.id, 'url': r.url} for r in self.references],
            'remediation': self.remediation,
            'exploitability': self.exploitability,
            'published_date': self.published_date,
            'llm_severity_validation': self.llm_severity_validation,
            'llm_explanation': self.llm_explanation,
            'llm_exploitability_assessment': self.llm_exploitability_assessment,
            'llm_remediation_steps': self.llm_remediation_steps,
            'llm_code_example': self.llm_code_example,
            'scan_timestamp': self.scan_timestamp,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Vulnerability':
        """Create Vulnerability from dictionary"""
        severity = Severity.from_string(data.get('severity', 'unknown'))
        
        references = [
            VulnerabilityReference(
                type=r['type'],
                id=r['id'],
                url=r.get('url')
            )
            for r in data.get('references', [])
        ]
        
        return cls(
            tool=data.get('tool', ''),
            vulnerability_id=data.get('vulnerability_id', ''),
            title=data.get('title', ''),
            description=data.get('description', ''),
            severity=severity,
            cvss_score=data.get('cvss_score'),
            cvss_vector=data.get('cvss_vector'),
            affected_component=data.get('affected_component', ''),
            affected_version=data.get('affected_version', ''),
            fixed_version=data.get('fixed_version', ''),
            file_path=data.get('file_path'),
            line_number=data.get('line_number'),
            vulnerability_type=data.get('vulnerability_type', ''),
            cwe_id=data.get('cwe_id'),
            references=references,
            remediation=data.get('remediation', ''),
            exploitability=data.get('exploitability'),
            published_date=data.get('published_date'),
            llm_severity_validation=data.get('llm_severity_validation'),
            llm_explanation=data.get('llm_explanation'),
            llm_exploitability_assessment=data.get('llm_exploitability_assessment'),
            llm_remediation_steps=data.get('llm_remediation_steps'),
            llm_code_example=data.get('llm_code_example'),
            scan_timestamp=data.get('scan_timestamp', datetime.utcnow().isoformat()),
        )


@dataclass
class ScanResult:
    """
    Complete scan result containing all vulnerabilities and metadata.
    
    This represents the output from the Scanner Layer (Chapter 3, Section 3.2.2)
    """
    target: str  # What was scanned
    scan_type: str  # "filesystem", "container", "dependencies", etc.
    tools_used: List[str]
    vulnerabilities: List[Vulnerability]
    scan_duration: float  # seconds
    scan_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'unknown': 0
        }
        
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity.value.lower()] += 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': severity_counts,
            'tools_used': self.tools_used,
            'scan_duration_seconds': round(self.scan_duration, 2),
            'scan_timestamp': self.scan_timestamp
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary"""
        return {
            'target': self.target,
            'scan_type': self.scan_type,
            'tools_used': self.tools_used,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'scan_duration': self.scan_duration,
            'scan_timestamp': self.scan_timestamp,
            'metadata': self.metadata,
            'summary': self.get_summary()
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Export scan result as JSON string"""
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class LLMAnalysisResult:
    """
    Result from LLM analysis of a vulnerability.
    
    This structure represents the output from the LLM Analysis Layer
    (Chapter 3, Section 3.2.2).
    """
    vulnerability_id: str
    severity_validation: str
    explanation: str
    exploitability_assessment: str
    remediation_steps: List[str]
    code_example: Optional[str] = None
    confidence_score: Optional[float] = None
    processing_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'vulnerability_id': self.vulnerability_id,
            'severity_validation': self.severity_validation,
            'explanation': self.explanation,
            'exploitability_assessment': self.exploitability_assessment,
            'remediation_steps': self.remediation_steps,
            'code_example': self.code_example,
            'confidence_score': self.confidence_score,
            'processing_time': self.processing_time
        }
