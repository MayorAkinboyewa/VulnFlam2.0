"""
Scanner Output Parser Module

This module implements the Processing Layer from Chapter 3, Section 3.2.2.
It parses heterogeneous scanner outputs into the unified Vulnerability data model.
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from pathlib import Path

from models import Vulnerability, VulnerabilityReference, Severity


logger = logging.getLogger(__name__)


class ParserError(Exception):
    """Exception raised for parsing errors"""
    pass


class VulnerabilityParser:
    """
    Base class for vulnerability scanner output parsers.
    
    Implements the Parser Module from Chapter 3, Section 3.2.2.
    Each scanner type has a specific parser subclass.
    """
    
    def __init__(self, scanner_name: str):
        self.scanner_name = scanner_name
    
    def parse(self, output_file: str) -> List[Vulnerability]:
        """
        Parse scanner output file into list of Vulnerability objects
        
        Args:
            output_file: Path to scanner output file
            
        Returns:
            List of Vulnerability objects
        """
        raise NotImplementedError("Subclasses must implement parse()")
    
    def _read_json_file(self, file_path: str) -> Dict[str, Any]:
        """Safely read and parse JSON file"""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")
            raise ParserError(f"Invalid JSON: {e}")
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            raise ParserError(f"File not found: {file_path}")

    def _read_xml_file(self, file_path: str) -> ET.Element:
        """Safely read and parse XML file"""
        try:
            tree = ET.parse(file_path)
            return tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Invalid XML in {file_path}: {e}")
            raise ParserError(f"Invalid XML: {e}")
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            raise ParserError(f"File not found: {file_path}")


class BanditParser(VulnerabilityParser):
    """Parser for Bandit SAST output"""
    
    def __init__(self):
        super().__init__('bandit')
    
    def parse(self, output_file: str) -> List[Vulnerability]:
        """
        Parse Bandit JSON output
        
        Bandit output format:
        {
            "results": [
                {
                    "code": "...",
                    "filename": "...",
                    "issue_confidence": "HIGH",
                    "issue_severity": "HIGH",
                    "issue_text": "...",
                    "line_number": 10,
                    "line_range": [10, 11],
                    "more_info": "https://...",
                    "test_id": "B201",
                    "test_name": "flask_debug_true"
                }
            ]
        }
        """
        logger.info(f"Parsing Bandit output: {output_file}")
        data = self._read_json_file(output_file)
        
        vulnerabilities = []
        
        for result in data.get('results', []):
            # Extract CWE from test_id if available
            test_id = result.get('test_id', '')
            cwe_id = None
            if 'CWE' in result.get('more_info', ''):
                # Try to extract CWE from URL
                import re
                cwe_match = re.search(r'CWE-(\d+)', result.get('more_info', ''))
                if cwe_match:
                    cwe_id = f"CWE-{cwe_match.group(1)}"
            
            # Convert Bandit severity to our Severity enum
            severity_str = result.get('issue_severity', 'UNKNOWN')
            severity = Severity.from_string(severity_str)
            
            vuln = Vulnerability(
                tool=self.scanner_name,
                vulnerability_id=test_id,
                title=result.get('test_name', 'Unknown vulnerability'),
                description=result.get('issue_text', ''),
                severity=severity,
                affected_component=result.get('filename', ''),
                file_path=result.get('filename'),
                line_number=result.get('line_number'),
                vulnerability_type=result.get('test_name', ''),
                cwe_id=cwe_id,
                references=[
                    VulnerabilityReference(
                        type='URL',
                        id='Bandit Documentation',
                        url=result.get('more_info')
                    )
                ] if result.get('more_info') else [],
                raw_data=result
            )
            
            vulnerabilities.append(vuln)
        
        logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from Bandit")
        return vulnerabilities


class TrivyParser(VulnerabilityParser):
    """Parser for Trivy vulnerability scanner output"""
    
    def __init__(self):
        super().__init__('trivy')
    
    def parse(self, output_file: str) -> List[Vulnerability]:
        """
        Parse Trivy JSON output
        
        Trivy output format (filesystem scan):
        {
            "Results": [
                {
                    "Target": "...",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-xxxxx",
                            "PkgName": "package-name",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.0.1",
                            "Severity": "HIGH",
                            "Title": "...",
                            "Description": "...",
                            "References": ["https://..."],
                            "PrimaryURL": "https://...",
                            "CVSS": {...}
                        }
                    ]
                }
            ]
        }
        """
        logger.info(f"Parsing Trivy output: {output_file}")
        data = self._read_json_file(output_file)
        
        vulnerabilities = []
        
        for result in data.get('Results', []):
            target = result.get('Target', '')
            
            for vuln_data in result.get('Vulnerabilities', []):
                # Extract CVSS score
                cvss_score = None
                cvss_vector = None
                cvss_info = vuln_data.get('CVSS', {})
                if isinstance(cvss_info, dict):
                    # Trivy might have multiple CVSS versions
                    for vendor, cvss_obj in cvss_info.items():
                        if isinstance(cvss_obj, dict) and 'V3Score' in cvss_obj:
                            cvss_score = cvss_obj.get('V3Score')
                            cvss_vector = cvss_obj.get('V3Vector')
                            break
                
                # Convert severity
                severity_str = vuln_data.get('Severity', 'UNKNOWN')
                severity = Severity.from_string(severity_str)
                
                # Extract CWE
                cwe_ids = vuln_data.get('CweIDs', [])
                cwe_id = cwe_ids[0] if cwe_ids else None
                
                vuln = Vulnerability(
                    tool=self.scanner_name,
                    vulnerability_id=vuln_data.get('VulnerabilityID', ''),
                    title=vuln_data.get('Title', ''),
                    description=vuln_data.get('Description', ''),
                    severity=severity,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    affected_component=vuln_data.get('PkgName', ''),
                    affected_version=vuln_data.get('InstalledVersion', ''),
                    fixed_version=vuln_data.get('FixedVersion', ''),
                    file_path=target,
                    vulnerability_type='Dependency Vulnerability',
                    cwe_id=cwe_id,
                    references=[
                        VulnerabilityReference(
                            type='URL',
                            id=ref,
                            url=ref
                        )
                        for ref in vuln_data.get('References', [])[:3]  # Limit to 3 refs
                    ],
                    remediation=f"Upgrade {vuln_data.get('PkgName', 'package')} to version {vuln_data.get('FixedVersion', 'latest')}" if vuln_data.get('FixedVersion') else "",
                    published_date=vuln_data.get('PublishedDate'),
                    raw_data=vuln_data
                )
                
                vulnerabilities.append(vuln)
        
        logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from Trivy")
        return vulnerabilities


class SafetyParser(VulnerabilityParser):
    """Parser for Safety Python dependency checker output"""
    
    def __init__(self):
        super().__init__('safety')
    
    def parse(self, output_file: str) -> List[Vulnerability]:
        """
        Parse Safety JSON output
        
        Safety output format:
        [
            [
                "package-name",
                "<1.0.0",
                "1.0.1",
                "CVE description",
                "12345"  // Safety DB ID
            ]
        ]
        """
        logger.info(f"Parsing Safety output: {output_file}")
        data = self._read_json_file(output_file)
        
        vulnerabilities = []
        
        for vuln_data in data:
            if not isinstance(vuln_data, list) or len(vuln_data) < 5:
                continue
            
            package_name = vuln_data[0]
            affected_versions = vuln_data[1]
            fixed_version = vuln_data[2]
            description = vuln_data[3]
            safety_id = vuln_data[4]
            
            # Safety doesn't always provide CVE IDs
            vulnerability_id = f"SAFETY-{safety_id}"
            
            vuln = Vulnerability(
                tool=self.scanner_name,
                vulnerability_id=vulnerability_id,
                title=f"Vulnerability in {package_name}",
                description=description,
                severity=Severity.HIGH,  # Safety doesn't provide severity, assume HIGH
                affected_component=package_name,
                affected_version=affected_versions,
                fixed_version=fixed_version,
                vulnerability_type='Dependency Vulnerability',
                remediation=f"Upgrade {package_name} to version {fixed_version} or higher",
                raw_data={'safety_data': vuln_data}
            )
            
            vulnerabilities.append(vuln)
        
        logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from Safety")
        return vulnerabilities


class SemgrepParser(VulnerabilityParser):
    """Parser for Semgrep SAST output"""
    
    def __init__(self):
        super().__init__('semgrep')
    
    def parse(self, output_file: str) -> List[Vulnerability]:
        """
        Parse Semgrep JSON output
        
        Semgrep output format:
        {
            "results": [
                {
                    "check_id": "rule-id",
                    "path": "file/path.py",
                    "start": {"line": 10, "col": 1},
                    "end": {"line": 10, "col": 20},
                    "extra": {
                        "message": "...",
                        "metadata": {
                            "cwe": ["CWE-89"],
                            "owasp": ["A1:2017-Injection"],
                            "severity": "ERROR"
                        },
                        "severity": "ERROR",
                        "lines": "..."
                    }
                }
            ]
        }
        """
        logger.info(f"Parsing Semgrep output: {output_file}")
        data = self._read_json_file(output_file)
        
        vulnerabilities = []
        
        for result in data.get('results', []):
            extra = result.get('extra', {})
            metadata = extra.get('metadata', {})
            
            # Extract severity
            severity_str = metadata.get('severity', extra.get('severity', 'MEDIUM'))
            # Semgrep uses ERROR, WARNING, INFO
            severity_map = {
                'ERROR': 'HIGH',
                'WARNING': 'MEDIUM',
                'INFO': 'LOW'
            }
            severity = Severity.from_string(severity_map.get(severity_str, severity_str))
            
            # Extract CWE
            cwe_list = metadata.get('cwe', [])
            cwe_id = cwe_list[0] if cwe_list else None
            
            # Extract line number
            line_number = result.get('start', {}).get('line')
            
            vuln = Vulnerability(
                tool=self.scanner_name,
                vulnerability_id=result.get('check_id', ''),
                title=metadata.get('category', result.get('check_id', '')),
                description=extra.get('message', ''),
                severity=severity,
                affected_component=result.get('path', ''),
                file_path=result.get('path'),
                line_number=line_number,
                vulnerability_type=metadata.get('category', 'Code Vulnerability'),
                cwe_id=cwe_id,
                references=[
                    VulnerabilityReference(
                        type='OWASP',
                        id=owasp_id,
                        url=None
                    )
                    for owasp_id in metadata.get('owasp', [])
                ],
                raw_data=result
            )
            
            vulnerabilities.append(vuln)
        
        logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from Semgrep")
        return vulnerabilities


class NiktoParser(VulnerabilityParser):
    """Parser for Nikto web server vulnerability scanner XML output."""

    def __init__(self):
        super().__init__('nikto')

    _HIGH_KEYWORDS = [
        'sql injection', 'xss', 'cross-site scripting', 'remote code execution',
        'rce', 'command injection', 'directory traversal', 'path traversal',
        'authentication bypass', 'arbitrary file', 'shellshock', 'heartbleed',
        'default credentials', 'default password', 'code execution',
    ]
    _MEDIUM_KEYWORDS = [
        'csrf', 'cross-site request', 'information disclosure', 'sensitive data',
        'backup file', 'config file', 'debug', 'phpinfo', 'server-status',
        'directory listing', 'file upload', 'unrestricted upload',
    ]

    def _estimate_severity(self, description: str, osvdb_id: str) -> Severity:
        """Estimate severity from description keywords and OSVDB ID presence."""
        desc_lower = description.lower()
        if any(kw in desc_lower for kw in self._HIGH_KEYWORDS):
            return Severity.HIGH
        if any(kw in desc_lower for kw in self._MEDIUM_KEYWORDS):
            return Severity.MEDIUM
        # A non-zero OSVDB ID means it maps to a known vulnerability entry
        if osvdb_id and osvdb_id != '0':
            return Severity.MEDIUM
        return Severity.INFO

    def parse(self, output_file: str) -> List[Vulnerability]:
        """
        Parse Nikto XML output.

        Nikto XML format:
        <niktoscan>
          <scandetails targetip="..." targetport="80" targetbanner="...">
            <item id="..." osvdbid="12345" osvdblink="..." method="GET">
              <description>...</description>
              <uri>/path</uri>
            </item>
          </scandetails>
        </niktoscan>
        """
        logger.info(f"Parsing Nikto output: {output_file}")

        try:
            root = self._read_xml_file(output_file)
        except ParserError as e:
            logger.error(f"Failed to parse Nikto XML: {e}")
            return []

        vulnerabilities = []

        for scandetails in root.findall('.//scandetails'):
            target_ip = scandetails.get('targetip', '')
            target_port = scandetails.get('targetport', '80')
            target_banner = scandetails.get('targetbanner', '')
            component = f"{target_ip}:{target_port}"

            for item in scandetails.findall('item'):
                item_id = item.get('id', '')
                osvdb_id = item.get('osvdbid', '0')
                osvdb_link = item.get('osvdblink', '')
                method = item.get('method', 'GET')

                desc_el = item.find('description')
                uri_el = item.find('uri')

                description = (desc_el.text or '').strip() if desc_el is not None else ''
                uri = (uri_el.text or '/').strip() if uri_el is not None else '/'

                if not description:
                    continue

                severity = self._estimate_severity(description, osvdb_id)
                vuln_id = f"OSVDB-{osvdb_id}" if osvdb_id and osvdb_id != '0' else f"NIKTO-{item_id}"

                references = []
                if osvdb_link:
                    references.append(VulnerabilityReference(
                        type='URL',
                        id=f"OSVDB-{osvdb_id}",
                        url=osvdb_link
                    ))

                short_title = description[:100] + ('...' if len(description) > 100 else '')

                vuln = Vulnerability(
                    tool=self.scanner_name,
                    vulnerability_id=vuln_id,
                    title=short_title,
                    description=f"[{method} {uri}] {description}",
                    severity=severity,
                    affected_component=component,
                    file_path=uri,
                    vulnerability_type='Web Vulnerability',
                    references=references,
                    remediation=f"Investigate and remediate the issue found at {uri}",
                    raw_data={
                        'item_id': item_id,
                        'osvdb_id': osvdb_id,
                        'method': method,
                        'uri': uri,
                        'target_banner': target_banner,
                    }
                )
                vulnerabilities.append(vuln)

        logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from Nikto")
        return vulnerabilities


class NmapParser(VulnerabilityParser):
    """Parser for Nmap XML output produced by NSE vulnerability scripts."""

    def __init__(self):
        super().__init__('nmap')

    _CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}')
    _CVSS_RE = re.compile(r'CVSSv\d[:\s]+(\d+\.?\d*)\s*\((\w+)\)', re.IGNORECASE)
    _RISK_RE = re.compile(r'Risk factor[:\s]+(\w+)', re.IGNORECASE)

    def _parse_vuln_script(
        self,
        script_el: ET.Element,
        host: str,
        port_id: str,
        service: str,
    ) -> Optional[Vulnerability]:
        """Parse a single NSE script element; returns None if not vulnerable."""
        script_id = script_el.get('id', '')
        output = script_el.get('output', '')

        if 'VULNERABLE' not in output and 'LIKELY VULNERABLE' not in output:
            return None

        cve_ids = self._CVE_RE.findall(output)
        vuln_id = cve_ids[0] if cve_ids else f"NMAP-{script_id}"

        # Determine severity from risk factor or CVSS score in script output
        severity = Severity.MEDIUM
        cvss_score = None

        risk_match = self._RISK_RE.search(output)
        if risk_match:
            severity = Severity.from_string(risk_match.group(1))

        cvss_match = self._CVSS_RE.search(output)
        if cvss_match:
            try:
                cvss_score = float(cvss_match.group(1))
                severity = Severity.from_cvss(cvss_score)
            except ValueError:
                pass

        # Prefer structured child elements when present
        title = script_id
        description = output.strip()

        title_el = script_el.find('.//elem[@key="title"]')
        if title_el is not None and title_el.text:
            title = title_el.text.strip()

        desc_el = script_el.find('.//elem[@key="description"]')
        if desc_el is not None and desc_el.text:
            description = desc_el.text.strip()

        references = [
            VulnerabilityReference(
                type='CVE',
                id=cve,
                url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"
            )
            for cve in cve_ids
        ]

        component = f"{host}:{port_id} ({service})" if service else f"{host}:{port_id}"

        return Vulnerability(
            tool=self.scanner_name,
            vulnerability_id=vuln_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            affected_component=component,
            file_path=f"{host}:{port_id}",
            vulnerability_type='Network Vulnerability',
            references=references,
            remediation=f"Apply patches or mitigations for {vuln_id} on {host}:{port_id}",
            raw_data={'script_id': script_id, 'host': host, 'port': port_id},
        )

    def parse(self, output_file: str) -> List[Vulnerability]:
        """
        Parse Nmap XML output from a vuln-script scan.

        Produces two finding types:
        - Confirmed vulnerabilities from NSE vuln scripts (MEDIUM–CRITICAL)
        - Open port/service inventory entries (INFO)
        """
        logger.info(f"Parsing Nmap output: {output_file}")

        try:
            root = self._read_xml_file(output_file)
        except ParserError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return []

        vulnerabilities = []

        for host_el in root.findall('.//host'):
            addr_el = host_el.find('address[@addrtype="ipv4"]')
            if addr_el is None:
                addr_el = host_el.find('address[@addrtype="ipv6"]')
            host = addr_el.get('addr', 'unknown') if addr_el is not None else 'unknown'

            for port_el in host_el.findall('.//port'):
                port_id = port_el.get('portid', '0')
                protocol = port_el.get('protocol', 'tcp')

                state_el = port_el.find('state')
                if state_el is None or state_el.get('state') != 'open':
                    continue

                service_el = port_el.find('service')
                service_name = service_product = service_version = ''
                if service_el is not None:
                    service_name = service_el.get('name', '')
                    service_product = service_el.get('product', '')
                    service_version = service_el.get('version', '')
                service_str = f"{service_product} {service_version}".strip() or service_name

                # Informational open-port entry
                vulnerabilities.append(Vulnerability(
                    tool=self.scanner_name,
                    vulnerability_id=f"NMAP-OPEN-{host}-{port_id}-{protocol}",
                    title=f"Open Port: {port_id}/{protocol} ({service_name})",
                    description=(
                        f"Port {port_id}/{protocol} is open on {host}. "
                        f"Service: {service_str}"
                    ),
                    severity=Severity.INFO,
                    affected_component=f"{host}:{port_id}",
                    file_path=f"{host}:{port_id}",
                    vulnerability_type='Open Port',
                    raw_data={
                        'host': host,
                        'port': port_id,
                        'protocol': protocol,
                        'service': service_str,
                    },
                ))

                # Per-port NSE vulnerability script findings
                for script_el in port_el.findall('script'):
                    vuln = self._parse_vuln_script(script_el, host, port_id, service_str)
                    if vuln:
                        vulnerabilities.append(vuln)

            # Host-level scripts (e.g. smb-vuln-*)
            hostscript_el = host_el.find('hostscript')
            if hostscript_el is not None:
                for script_el in hostscript_el.findall('script'):
                    vuln = self._parse_vuln_script(script_el, host, '0', '')
                    if vuln:
                        vulnerabilities.append(vuln)

        logger.info(f"Parsed {len(vulnerabilities)} findings from Nmap")
        return vulnerabilities


class ParserFactory:
    """
    Factory for creating appropriate parser based on scanner name.
    
    Implements the Parser Module from Chapter 3, Section 3.2.2.
    """
    
    PARSERS = {
        'bandit': BanditParser,
        'trivy': TrivyParser,
        'safety': SafetyParser,
        'semgrep': SemgrepParser,
        'nikto': NiktoParser,
        'nmap': NmapParser,
    }
    
    @staticmethod
    def get_parser(scanner_name: str) -> Optional[VulnerabilityParser]:
        """Get appropriate parser for scanner"""
        parser_class = ParserFactory.PARSERS.get(scanner_name.lower())
        if parser_class:
            return parser_class()
        logger.warning(f"No parser available for scanner: {scanner_name}")
        return None
    
    @staticmethod
    def parse_scan_output(scanner_name: str, output_file: str) -> List[Vulnerability]:
        """
        Parse scanner output file using appropriate parser
        
        Args:
            scanner_name: Name of the scanner
            output_file: Path to scanner output file
            
        Returns:
            List of parsed vulnerabilities
        """
        parser = ParserFactory.get_parser(scanner_name)
        if not parser:
            logger.error(f"Cannot parse output from unknown scanner: {scanner_name}")
            return []
        
        try:
            return parser.parse(output_file)
        except Exception as e:
            logger.error(f"Error parsing {scanner_name} output: {e}", exc_info=True)
            return []


def deduplicate_vulnerabilities(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
    """
    Remove duplicate vulnerabilities based on vulnerability ID and affected component.
    
    This implements the deduplication logic mentioned in the technical requirements.
    
    Args:
        vulnerabilities: List of vulnerabilities potentially containing duplicates
        
    Returns:
        List of unique vulnerabilities
    """
    seen = set()
    unique = []
    
    for vuln in vulnerabilities:
        # Create a unique key based on vulnerability ID and affected component
        key = (vuln.vulnerability_id, vuln.affected_component)
        
        if key not in seen:
            seen.add(key)
            unique.append(vuln)
        else:
            logger.debug(f"Skipping duplicate: {key}")
    
    logger.info(f"Deduplicated {len(vulnerabilities)} vulnerabilities to {len(unique)} unique")
    return unique
