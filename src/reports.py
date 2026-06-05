"""
Report Generation Module

This module implements the Reporting Layer from Chapter 3, Section 3.2.2.
It generates developer-ready reports in multiple formats (HTML, Markdown, JSON).
"""

import json
import logging
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path

from models import Vulnerability, ScanResult, Severity


logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates vulnerability reports in multiple formats.
    
    Implements the Reporting Layer from Chapter 3, Section 3.2.2 and
    the report structure from Chapter 3, Section 3.5.
    """
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_json_report(
        self,
        scan_result: ScanResult,
        output_file: Optional[str] = None
    ) -> str:
        """
        Generate JSON format report.
        
        JSON reports are machine-readable for CI/CD integration and
        programmatic processing (Chapter 3, Section 3.5.2).
        
        Args:
            scan_result: Complete scan results
            output_file: Optional custom output file path
            
        Returns:
            Path to generated JSON file
        """
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"vulnerability_report_{timestamp}.json"
        
        report_data = scan_result.to_dict()
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"JSON report generated: {output_file}")
        return str(output_file)
    
    def generate_markdown_report(
        self,
        scan_result: ScanResult,
        output_file: Optional[str] = None
    ) -> str:
        """
        Generate Markdown format report.
        
        Markdown reports are VCS-friendly and can be committed alongside code
        for historical reference (Chapter 3, Section 3.5.2).
        
        Args:
            scan_result: Complete scan results
            output_file: Optional custom output file path
            
        Returns:
            Path to generated Markdown file
        """
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"vulnerability_report_{timestamp}.md"
        
        md_parts = []
        
        # Header
        md_parts.extend([
            "# Vulnerability Assessment Report",
            "",
            f"**Target**: {scan_result.target}",
            f"**Scan Type**: {scan_result.scan_type}",
            f"**Generated**: {scan_result.scan_timestamp}",
            f"**Scan Duration**: {scan_result.scan_duration:.2f} seconds",
            "",
            "---",
            ""
        ])
        
        # Executive Summary
        summary = scan_result.get_summary()
        md_parts.extend([
            "## Executive Summary",
            "",
            f"**Total Vulnerabilities Found**: {summary['total_vulnerabilities']}",
            "",
            "### Severity Breakdown",
            "",
            f"- **Critical**: {summary['severity_breakdown']['critical']}",
            f"- **High**: {summary['severity_breakdown']['high']}",
            f"- **Medium**: {summary['severity_breakdown']['medium']}",
            f"- **Low**: {summary['severity_breakdown']['low']}",
            f"- **Info**: {summary['severity_breakdown']['info']}",
            "",
            f"**Scanning Tools Used**: {', '.join(summary['tools_used'])}",
            "",
            "---",
            ""
        ])
        
        # Critical Findings (if any)
        critical_vulns = [v for v in scan_result.vulnerabilities if v.severity == Severity.CRITICAL]
        if critical_vulns:
            md_parts.extend([
                "## ⚠️ Critical Findings Requiring Immediate Attention",
                "",
            ])
            for vuln in critical_vulns:
                md_parts.extend(self._format_vulnerability_markdown(vuln, detailed=True))
            md_parts.append("---\n")
        
        # Detailed Findings by Severity
        for severity in [Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            vulns = [v for v in scan_result.vulnerabilities if v.severity == severity]
            if vulns:
                md_parts.extend([
                    f"## {severity.value} Severity Vulnerabilities ({len(vulns)})",
                    ""
                ])
                for vuln in vulns:
                    md_parts.extend(self._format_vulnerability_markdown(vuln, detailed=False))
                md_parts.append("")
        
        # Appendix
        md_parts.extend([
            "---",
            "",
            "## Appendix",
            "",
            "### Methodology",
            "",
            "This report was generated using an LLM-enhanced DevSecOps pipeline that:",
            "1. Executes multiple vulnerability scanning tools",
            "2. Normalizes and deduplicates findings across tools",
            "3. Analyzes vulnerabilities using Large Language Models for contextual understanding",
            "4. Generates actionable remediation guidance tailored to your codebase",
            "",
            "### Scan Metadata",
            "",
            f"- **Scan Target**: {scan_result.target}",
            f"- **Scan Type**: {scan_result.scan_type}",
            f"- **Timestamp**: {scan_result.scan_timestamp}",
            f"- **Tools**: {', '.join(scan_result.tools_used)}",
            ""
        ])
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write('\n'.join(md_parts))
        
        logger.info(f"Markdown report generated: {output_file}")
        return str(output_file)
    
    def _format_vulnerability_markdown(self, vuln: Vulnerability, detailed: bool = False) -> List[str]:
        """Format a single vulnerability in Markdown"""
        lines = [
            f"### {vuln.vulnerability_id}: {vuln.title}",
            ""
        ]
        
        # Basic info
        lines.extend([
            f"**Severity**: {vuln.severity.value}",
            f"**Tool**: {vuln.tool}",
            f"**Affected Component**: {vuln.affected_component}",
        ])
        
        if vuln.cvss_score:
            lines.append(f"**CVSS Score**: {vuln.cvss_score}")
        
        if vuln.file_path:
            location = f"{vuln.file_path}"
            if vuln.line_number:
                location += f":{vuln.line_number}"
            lines.append(f"**Location**: `{location}`")
        
        if vuln.affected_version:
            lines.append(f"**Affected Version**: {vuln.affected_version}")
        
        if vuln.fixed_version:
            lines.append(f"**Fixed In**: {vuln.fixed_version}")
        
        lines.append("")
        
        # LLM-enhanced explanation (if available)
        if vuln.llm_explanation:
            lines.extend([
                "**Analysis**:",
                "",
                vuln.llm_explanation,
                ""
            ])
        else:
            lines.extend([
                "**Description**:",
                "",
                vuln.description,
                ""
            ])
        
        # Exploitability assessment (if available)
        if vuln.llm_exploitability_assessment and detailed:
            lines.extend([
                "**Exploitability**:",
                "",
                vuln.llm_exploitability_assessment,
                ""
            ])
        
        # Remediation
        if vuln.llm_remediation_steps:
            lines.extend([
                "**Remediation Steps**:",
                ""
            ])
            for i, step in enumerate(vuln.llm_remediation_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")
            
            if vuln.llm_code_example:
                lines.extend([
                    "**Code Example**:",
                    "",
                    "```",
                    vuln.llm_code_example,
                    "```",
                    ""
                ])
        elif vuln.remediation:
            lines.extend([
                "**Remediation**:",
                "",
                vuln.remediation,
                ""
            ])
        
        # References
        if vuln.references:
            lines.append("**References**:")
            lines.append("")
            for ref in vuln.references:
                if ref.url:
                    lines.append(f"- [{ref.id}]({ref.url})")
                else:
                    lines.append(f"- {ref.id}")
            lines.append("")
        
        lines.append("---\n")
        return lines
    
    def generate_html_report(
        self,
        scan_result: ScanResult,
        output_file: Optional[str] = None
    ) -> str:
        """
        Generate HTML format report.
        
        HTML reports are interactive and optimized for human review
        with syntax highlighting and collapsible sections (Chapter 3, Section 3.5.2).
        
        Args:
            scan_result: Complete scan results
            output_file: Optional custom output file path
            
        Returns:
            Path to generated HTML file
        """
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"vulnerability_report_{timestamp}.html"
        
        summary = scan_result.get_summary()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Assessment Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
        }}
        .summary {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .severity-box {{
            padding: 15px;
            border-radius: 6px;
            text-align: center;
            color: white;
        }}
        .severity-critical {{ background-color: #dc2626; }}
        .severity-high {{ background-color: #ea580c; }}
        .severity-medium {{ background-color: #f59e0b; }}
        .severity-low {{ background-color: #3b82f6; }}
        .severity-info {{ background-color: #6b7280; }}
        .vulnerability {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #ddd;
        }}
        .vulnerability.critical {{ border-left-color: #dc2626; }}
        .vulnerability.high {{ border-left-color: #ea580c; }}
        .vulnerability.medium {{ border-left-color: #f59e0b; }}
        .vulnerability.low {{ border-left-color: #3b82f6; }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 15px;
        }}
        .vuln-title {{
            font-size: 1.2em;
            font-weight: 600;
            color: #1f2937;
        }}
        .severity-badge {{
            padding: 5px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
            color: white;
        }}
        .meta-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin: 15px 0;
            padding: 15px;
            background: #f9fafb;
            border-radius: 4px;
        }}
        .meta-item {{
            font-size: 0.9em;
        }}
        .meta-label {{
            font-weight: 600;
            color: #6b7280;
        }}
        .section {{
            margin: 20px 0;
        }}
        .section-title {{
            font-weight: 600;
            color: #374151;
            margin-bottom: 10px;
        }}
        .remediation-steps {{
            background: #ecfdf5;
            border-left: 3px solid #10b981;
            padding: 15px;
            border-radius: 4px;
        }}
        .remediation-steps ol {{
            margin: 10px 0;
            padding-left: 25px;
        }}
        code {{
            background: #f3f4f6;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        pre {{
            background: #1f2937;
            color: #f9fafb;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e5e7eb;
            color: #6b7280;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Vulnerability Assessment Report</h1>
        <p><strong>Target:</strong> {scan_result.target}</p>
        <p><strong>Generated:</strong> {scan_result.scan_timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Total vulnerabilities found: <strong>{summary['total_vulnerabilities']}</strong></p>
        <p>Scan duration: <strong>{summary['scan_duration_seconds']} seconds</strong></p>
        <p>Tools used: <strong>{', '.join(summary['tools_used'])}</strong></p>
        
        <div class="severity-grid">
            <div class="severity-box severity-critical">
                <div style="font-size: 2em; font-weight: bold;">{summary['severity_breakdown']['critical']}</div>
                <div>Critical</div>
            </div>
            <div class="severity-box severity-high">
                <div style="font-size: 2em; font-weight: bold;">{summary['severity_breakdown']['high']}</div>
                <div>High</div>
            </div>
            <div class="severity-box severity-medium">
                <div style="font-size: 2em; font-weight: bold;">{summary['severity_breakdown']['medium']}</div>
                <div>Medium</div>
            </div>
            <div class="severity-box severity-low">
                <div style="font-size: 2em; font-weight: bold;">{summary['severity_breakdown']['low']}</div>
                <div>Low</div>
            </div>
            <div class="severity-box severity-info">
                <div style="font-size: 2em; font-weight: bold;">{summary['severity_breakdown']['info']}</div>
                <div>Info</div>
            </div>
        </div>
    </div>
"""
        
        # Generate vulnerability cards
        for vuln in sorted(scan_result.vulnerabilities, key=lambda v: (v.severity.value, v.vulnerability_id)):
            html += self._format_vulnerability_html(vuln)
        
        html += f"""
    <div class="footer">
        <p><strong>Report Generation Method:</strong> LLM-Enhanced DevSecOps Pipeline</p>
        <p>This report combines automated vulnerability scanning with AI-powered analysis to provide 
        contextual understanding and actionable remediation guidance.</p>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        logger.info(f"HTML report generated: {output_file}")
        return str(output_file)
    
    def _format_vulnerability_html(self, vuln: Vulnerability) -> str:
        """Format a single vulnerability in HTML"""
        severity_class = vuln.severity.value.lower()
        
        html = f"""
    <div class="vulnerability {severity_class}">
        <div class="vuln-header">
            <div class="vuln-title">{vuln.vulnerability_id}: {vuln.title}</div>
            <div class="severity-badge severity-{severity_class}">{vuln.severity.value}</div>
        </div>
        
        <div class="meta-info">
            <div class="meta-item">
                <span class="meta-label">Tool:</span> {vuln.tool}
            </div>
            <div class="meta-item">
                <span class="meta-label">Component:</span> <code>{vuln.affected_component}</code>
            </div>
"""
        
        if vuln.cvss_score:
            html += f"""
            <div class="meta-item">
                <span class="meta-label">CVSS Score:</span> {vuln.cvss_score}
            </div>
"""
        
        if vuln.file_path:
            location = vuln.file_path
            if vuln.line_number:
                location += f":{vuln.line_number}"
            html += f"""
            <div class="meta-item">
                <span class="meta-label">Location:</span> <code>{location}</code>
            </div>
"""
        
        if vuln.affected_version:
            html += f"""
            <div class="meta-item">
                <span class="meta-label">Affected:</span> {vuln.affected_version}
            </div>
"""
        
        if vuln.fixed_version:
            html += f"""
            <div class="meta-item">
                <span class="meta-label">Fixed in:</span> {vuln.fixed_version}
            </div>
"""
        
        html += """
        </div>
"""
        
        # LLM Analysis
        if vuln.llm_explanation:
            html += f"""
        <div class="section">
            <div class="section-title">🤖 AI Analysis</div>
            <p>{vuln.llm_explanation}</p>
        </div>
"""
        
        if vuln.llm_exploitability_assessment:
            html += f"""
        <div class="section">
            <div class="section-title">⚠️ Exploitability Assessment</div>
            <p>{vuln.llm_exploitability_assessment}</p>
        </div>
"""
        
        # Remediation
        if vuln.llm_remediation_steps:
            steps_html = '\n'.join([f"<li>{step}</li>" for step in vuln.llm_remediation_steps])
            html += f"""
        <div class="remediation-steps">
            <div class="section-title">✅ Remediation Steps</div>
            <ol>
                {steps_html}
            </ol>
"""
            
            if vuln.llm_code_example:
                html += f"""
            <div class="section-title" style="margin-top: 15px;">Code Example</div>
            <pre>{vuln.llm_code_example}</pre>
"""
            html += """
        </div>
"""
        elif vuln.remediation:
            html += f"""
        <div class="section">
            <div class="section-title">Remediation</div>
            <p>{vuln.remediation}</p>
        </div>
"""
        
        html += """
    </div>
"""
        
        return html
    
    def generate_all_formats(self, scan_result: ScanResult) -> Dict[str, str]:
        """
        Generate reports in all formats (JSON, Markdown, HTML).
        
        Args:
            scan_result: Complete scan results
            
        Returns:
            Dictionary mapping format names to output file paths
        """
        outputs = {
            'json': self.generate_json_report(scan_result),
            'markdown': self.generate_markdown_report(scan_result),
            'html': self.generate_html_report(scan_result)
        }
        
        logger.info(f"Generated reports in all formats: {list(outputs.keys())}")
        return outputs
