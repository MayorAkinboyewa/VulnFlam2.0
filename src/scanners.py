"""
Scanner Orchestration Module

This module implements the Scanner Layer from Chapter 3, Section 3.2.2.
It manages execution of multiple vulnerability scanning tools and collects their outputs.
"""

import subprocess
import json
import logging
import os
import shutil
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


logger = logging.getLogger(__name__)


class ScannerConfig:
    """Configuration for a vulnerability scanner"""
    def __init__(self, name: str, command: str, output_format: str, enabled: bool = True):
        self.name = name
        self.command = command
        self.output_format = output_format  # 'json', 'xml', 'text'
        self.enabled = enabled


class ScannerOrchestrator:
    """
    Orchestrates multiple vulnerability scanning tools.
    
    Implements the Scanner Layer design from Chapter 3, Section 3.2.2.
    Executes configured scanners in parallel and collects outputs.
    """
    
    def __init__(self, output_dir: str = "/tmp/vuln_scans"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scanners: Dict[str, ScannerConfig] = {}
        self._register_default_scanners()
    
    def _register_default_scanners(self):
        """Register commonly available vulnerability scanners"""
        
        # Bandit - Python SAST
        self.scanners['bandit'] = ScannerConfig(
            name='bandit',
            command='bandit',
            output_format='json'
        )
        
        # Trivy - Container/filesystem vulnerability scanner
        self.scanners['trivy'] = ScannerConfig(
            name='trivy',
            command='trivy',
            output_format='json'
        )
        
        # Safety - Python dependency checker
        self.scanners['safety'] = ScannerConfig(
            name='safety',
            command='safety',
            output_format='json'
        )
        
        # Semgrep - Multi-language SAST
        self.scanners['semgrep'] = ScannerConfig(
            name='semgrep',
            command='semgrep',
            output_format='json'
        )
        
        # OWASP Dependency-Check
        self.scanners['dependency-check'] = ScannerConfig(
            name='dependency-check',
            command='dependency-check',
            output_format='json'
        )

        # Nikto - Web server vulnerability scanner
        self.scanners['nikto'] = ScannerConfig(
            name='nikto',
            command='nikto',
            output_format='xml'
        )

        # Nmap - Network port scanner with NSE vulnerability scripts
        self.scanners['nmap'] = ScannerConfig(
            name='nmap',
            command='nmap',
            output_format='xml'
        )
    
    def is_scanner_available(self, scanner_name: str) -> bool:
        """Check if a scanner is installed and available"""
        scanner = self.scanners.get(scanner_name)
        if not scanner:
            return False
        return shutil.which(scanner.command) is not None
    
    def get_available_scanners(self) -> List[str]:
        """Get list of scanners that are installed and available"""
        available = []
        for name in self.scanners:
            if self.is_scanner_available(name):
                available.append(name)
                logger.info(f"Scanner '{name}' is available")
            else:
                logger.warning(f"Scanner '{name}' is not available")
        return available
    
    def run_bandit(self, target_path: str) -> Optional[str]:
        """
        Run Bandit Python SAST scanner
        
        Args:
            target_path: Path to Python code to scan
            
        Returns:
            Path to output file or None if scan failed
        """
        output_file = self.output_dir / f"bandit_{int(time.time())}.json"
        
        cmd = [
            'bandit',
            '-r',  # Recursive
            target_path,
            '-f', 'json',  # JSON output
            '-o', str(output_file),
            '--exit-zero'  # Don't fail on findings
        ]
        
        try:
            logger.info(f"Running Bandit on {target_path}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if output_file.exists():
                logger.info(f"Bandit scan completed: {output_file}")
                return str(output_file)
            else:
                logger.error("Bandit scan failed to produce output")
                logger.error(f"STDERR: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timed out")
            return None
        except Exception as e:
            logger.error(f"Bandit scan error: {e}")
            return None
    
    def run_trivy(self, target_path: str, scan_type: str = 'fs') -> Optional[str]:
        """
        Run Trivy vulnerability scanner
        
        Args:
            target_path: Path to scan (filesystem, container image, etc.)
            scan_type: 'fs' for filesystem, 'image' for container image
            
        Returns:
            Path to output file or None if scan failed
        """
        output_file = self.output_dir / f"trivy_{int(time.time())}.json"
        
        cmd = [
            'trivy',
            scan_type,
            '--format', 'json',
            '--output', str(output_file),
            target_path
        ]
        
        try:
            logger.info(f"Running Trivy {scan_type} scan on {target_path}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            if output_file.exists():
                logger.info(f"Trivy scan completed: {output_file}")
                return str(output_file)
            else:
                logger.error("Trivy scan failed to produce output")
                logger.error(f"STDERR: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timed out")
            return None
        except Exception as e:
            logger.error(f"Trivy scan error: {e}")
            return None
    
    def run_safety(self, requirements_file: str) -> Optional[str]:
        """
        Run Safety Python dependency vulnerability checker
        
        Args:
            requirements_file: Path to requirements.txt
            
        Returns:
            Path to output file or None if scan failed
        """
        output_file = self.output_dir / f"safety_{int(time.time())}.json"
        
        cmd = [
            'safety',
            'check',
            '--file', requirements_file,
            '--json',
            '--output', str(output_file)
        ]
        
        try:
            logger.info(f"Running Safety on {requirements_file}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            if output_file.exists():
                logger.info(f"Safety scan completed: {output_file}")
                return str(output_file)
            else:
                # Safety might write to stdout if --output fails
                if result.stdout:
                    with open(output_file, 'w') as f:
                        f.write(result.stdout)
                    return str(output_file)
                logger.error("Safety scan failed to produce output")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Safety scan timed out")
            return None
        except Exception as e:
            logger.error(f"Safety scan error: {e}")
            return None
    
    def run_semgrep(self, target_path: str, rules: str = "auto") -> Optional[str]:
        """
        Run Semgrep SAST scanner
        
        Args:
            target_path: Path to code to scan
            rules: Semgrep rules to use ('auto', 'p/security-audit', etc.)
            
        Returns:
            Path to output file or None if scan failed
        """
        output_file = self.output_dir / f"semgrep_{int(time.time())}.json"
        
        cmd = [
            'semgrep',
            '--config', rules,
            '--json',
            '--output', str(output_file),
            target_path
        ]
        
        try:
            logger.info(f"Running Semgrep on {target_path} with rules: {rules}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            if output_file.exists():
                logger.info(f"Semgrep scan completed: {output_file}")
                return str(output_file)
            else:
                logger.error("Semgrep scan failed to produce output")
                logger.error(f"STDERR: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out")
            return None
        except Exception as e:
            logger.error(f"Semgrep scan error: {e}")
            return None
    
    def run_nikto(self, target: str) -> Optional[str]:
        """
        Run Nikto web server vulnerability scanner.

        Args:
            target: Target URL or host (e.g. http://192.168.1.1 or 192.168.1.1)

        Returns:
            Path to XML output file or None if scan failed
        """
        output_file = self.output_dir / f"nikto_{int(time.time())}.xml"

        parsed = urlparse(target if '://' in target else f'http://{target}')
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'

        cmd = [
            'nikto',
            '-h', host,
            '-port', str(port),
            '-Format', 'xml',
            '-o', str(output_file),
            '-nointeractive',
        ]
        if use_ssl:
            cmd.append('-ssl')

        try:
            logger.info(f"Running Nikto on {host}:{port}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900,  # 15 minute timeout
            )

            if output_file.exists() and output_file.stat().st_size > 0:
                logger.info(f"Nikto scan completed: {output_file}")
                return str(output_file)
            else:
                logger.error("Nikto scan failed to produce output")
                logger.error(f"STDERR: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("Nikto scan timed out after 15 minutes")
            return None
        except Exception as e:
            logger.error(f"Nikto scan error: {e}")
            return None

    def run_nmap(self, target: str) -> Optional[str]:
        """
        Run Nmap network scanner with NSE vulnerability scripts.

        Uses service/version detection (-sV) and the 'vuln' NSE script
        category to identify known vulnerabilities on open ports.

        Args:
            target: Target host/IP/URL to scan

        Returns:
            Path to XML output file or None if scan failed
        """
        output_file = self.output_dir / f"nmap_{int(time.time())}.xml"

        parsed = urlparse(target if '://' in target else f'http://{target}')
        host = parsed.hostname or target

        cmd = [
            'nmap',
            '-sV',              # Service/version detection
            '--script', 'vuln', # NSE vulnerability scripts
            '-T4',              # Aggressive timing for speed
            '--open',           # Only report open ports
            '-oX', str(output_file),
            host,
        ]

        try:
            logger.info(f"Running Nmap vulnerability scan on {host}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minute timeout
            )

            if output_file.exists() and output_file.stat().st_size > 0:
                logger.info(f"Nmap scan completed: {output_file}")
                return str(output_file)
            else:
                logger.error("Nmap scan failed to produce output")
                logger.error(f"STDERR: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out after 30 minutes")
            return None
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return None

    def run_all_scanners(
        self, 
        target_path: str,
        scan_type: str = 'filesystem',
        parallel: bool = True,
        max_workers: int = 4
    ) -> Dict[str, Optional[str]]:
        """
        Run all available scanners on the target
        
        Args:
            target_path: Path to scan
            scan_type: Type of scan ('filesystem', 'container', 'dependencies')
            parallel: Whether to run scanners in parallel
            max_workers: Maximum number of parallel scanner processes
            
        Returns:
            Dictionary mapping scanner names to output file paths
        """
        available_scanners = self.get_available_scanners()
        results = {}
        
        if not available_scanners:
            logger.warning("No scanners available")
            return results
        
        scan_tasks = []
        
        # Prepare scan tasks based on target type
        for scanner_name in available_scanners:
            if scanner_name == 'bandit':
                scan_tasks.append(('bandit', lambda: self.run_bandit(target_path)))
            elif scanner_name == 'trivy':
                if scan_type == 'container':
                    scan_tasks.append(('trivy', lambda: self.run_trivy(target_path, 'image')))
                else:
                    scan_tasks.append(('trivy', lambda: self.run_trivy(target_path, 'fs')))
            elif scanner_name == 'safety':
                # Look for requirements.txt
                req_file = Path(target_path) / 'requirements.txt'
                if req_file.exists():
                    scan_tasks.append(('safety', lambda: self.run_safety(str(req_file))))
            elif scanner_name == 'semgrep':
                scan_tasks.append(('semgrep', lambda: self.run_semgrep(target_path)))
            elif scanner_name == 'nikto':
                if scan_type == 'network':
                    scan_tasks.append(('nikto', lambda: self.run_nikto(target_path)))
            elif scanner_name == 'nmap':
                if scan_type == 'network':
                    scan_tasks.append(('nmap', lambda: self.run_nmap(target_path)))
        
        if parallel:
            # Run scans in parallel
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_scanner = {
                    executor.submit(task_func): scanner_name 
                    for scanner_name, task_func in scan_tasks
                }
                
                for future in as_completed(future_to_scanner):
                    scanner_name = future_to_scanner[future]
                    try:
                        output_file = future.result()
                        results[scanner_name] = output_file
                    except Exception as e:
                        logger.error(f"Scanner {scanner_name} failed: {e}")
                        results[scanner_name] = None
        else:
            # Run scans sequentially
            for scanner_name, task_func in scan_tasks:
                try:
                    output_file = task_func()
                    results[scanner_name] = output_file
                except Exception as e:
                    logger.error(f"Scanner {scanner_name} failed: {e}")
                    results[scanner_name] = None
        
        return results
