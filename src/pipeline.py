"""
Main Vulnerability Assessment Pipeline

This module implements the complete end-to-end pipeline described in Chapter 3,
orchestrating all components from scanning through LLM analysis to report generation.
"""

import logging
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

from models import Vulnerability, ScanResult, Severity
from scanners import ScannerOrchestrator
from parsers import ParserFactory, deduplicate_vulnerabilities
from llm_analyzer import LLMAnalyzer, MockLLMAnalyzer, LLMConfig
from reports import ReportGenerator


logger = logging.getLogger(__name__)


class VulnerabilityPipeline:
    """
    Complete vulnerability assessment pipeline.
    
    Implements the full data flow from Chapter 3, Section 3.2.3:
    1. Scanner Layer - Execute vulnerability scans
    2. Processing Layer - Parse and normalize outputs
    3. LLM Analysis Layer - Enhance with AI-powered analysis
    4. Reporting Layer - Generate developer-ready reports
    """
    
    def __init__(
        self,
        llm_config: Optional[LLMConfig] = None,
        use_mock_llm: bool = False,
        output_dir: str = "./reports"
    ):
        """
        Initialize the pipeline.
        
        Args:
            llm_config: Configuration for LLM API (None for mock)
            use_mock_llm: Use mock LLM instead of real API calls
            output_dir: Directory for reports
        """
        self.scanner_orchestrator = ScannerOrchestrator()
        self.report_generator = ReportGenerator(output_dir=output_dir)
        
        # Initialize LLM analyzer
        if use_mock_llm or llm_config is None:
            logger.info("Using Mock LLM Analyzer (no API calls)")
            self.llm_analyzer = MockLLMAnalyzer()
        else:
            logger.info(f"Using {llm_config.model} for LLM analysis")
            self.llm_analyzer = LLMAnalyzer(llm_config)
    
    def run(
        self,
        target_path: str,
        scan_type: str = 'filesystem',
        enable_llm: bool = True,
        report_formats: List[str] = ['json', 'markdown', 'html'],
        parallel_scans: bool = True
    ) -> ScanResult:
        """
        Execute the complete vulnerability assessment pipeline.
        
        This implements the 11-step data flow from Chapter 3, Section 3.2.3.
        
        Args:
            target_path: Path to code/application to scan
            scan_type: Type of scan ('filesystem', 'container', 'dependencies')
            enable_llm: Whether to enhance findings with LLM analysis
            report_formats: List of report formats to generate
            parallel_scans: Run scanners in parallel
            
        Returns:
            ScanResult containing all findings and metadata
        """
        logger.info("="*80)
        logger.info("Starting Vulnerability Assessment Pipeline")
        logger.info(f"Target: {target_path}")
        logger.info(f"Scan Type: {scan_type}")
        logger.info("="*80)
        
        pipeline_start = time.time()
        
        # Step 1-3: Scanner Layer - Execute scans
        logger.info("\n[1/4] SCANNER LAYER: Executing vulnerability scans...")
        scan_outputs = self.scanner_orchestrator.run_all_scanners(
            target_path=target_path,
            scan_type=scan_type,
            parallel=parallel_scans
        )
        
        successful_scans = {k: v for k, v in scan_outputs.items() if v is not None}
        logger.info(f"Completed {len(successful_scans)}/{len(scan_outputs)} scans successfully")
        
        if not successful_scans:
            logger.error("No scans completed successfully. Aborting pipeline.")
            raise RuntimeError("All scanner executions failed")
        
        # Step 4-5: Processing Layer - Parse and normalize
        logger.info("\n[2/4] PROCESSING LAYER: Parsing scanner outputs...")
        all_vulnerabilities = []
        
        for scanner_name, output_file in successful_scans.items():
            logger.info(f"Parsing {scanner_name} output: {output_file}")
            vulns = ParserFactory.parse_scan_output(scanner_name, output_file)
            all_vulnerabilities.extend(vulns)
            logger.info(f"  Found {len(vulns)} vulnerabilities in {scanner_name} output")
        
        logger.info(f"Total vulnerabilities before deduplication: {len(all_vulnerabilities)}")
        
        # Deduplicate
        all_vulnerabilities = deduplicate_vulnerabilities(all_vulnerabilities)
        logger.info(f"Total unique vulnerabilities: {len(all_vulnerabilities)}")
        
        # Step 6-8: LLM Analysis Layer (optional)
        if enable_llm and all_vulnerabilities:
            logger.info("\n[3/4] LLM ANALYSIS LAYER: Enhancing vulnerabilities with AI analysis...")
            all_vulnerabilities = self.llm_analyzer.enhance_vulnerabilities(all_vulnerabilities)
        else:
            logger.info("\n[3/4] LLM ANALYSIS LAYER: Skipped (disabled or no vulnerabilities found)")
        
        # Create scan result
        scan_duration = time.time() - pipeline_start
        scan_result = ScanResult(
            target=target_path,
            scan_type=scan_type,
            tools_used=list(successful_scans.keys()),
            vulnerabilities=all_vulnerabilities,
            scan_duration=scan_duration
        )
        
        # Step 9-11: Reporting Layer - Generate reports
        logger.info("\n[4/4] REPORTING LAYER: Generating reports...")
        
        report_paths = {}
        for format_type in report_formats:
            if format_type == 'json':
                path = self.report_generator.generate_json_report(scan_result)
                report_paths['json'] = path
            elif format_type == 'markdown':
                path = self.report_generator.generate_markdown_report(scan_result)
                report_paths['markdown'] = path
            elif format_type == 'html':
                path = self.report_generator.generate_html_report(scan_result)
                report_paths['html'] = path
        
        # Print summary
        logger.info("\n" + "="*80)
        logger.info("Pipeline Execution Complete")
        logger.info("="*80)
        summary = scan_result.get_summary()
        logger.info(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        logger.info(f"  Critical: {summary['severity_breakdown']['critical']}")
        logger.info(f"  High:     {summary['severity_breakdown']['high']}")
        logger.info(f"  Medium:   {summary['severity_breakdown']['medium']}")
        logger.info(f"  Low:      {summary['severity_breakdown']['low']}")
        logger.info(f"  Info:     {summary['severity_breakdown']['info']}")
        logger.info(f"\nScan Duration: {scan_duration:.2f} seconds")
        logger.info(f"Tools Used: {', '.join(summary['tools_used'])}")
        logger.info(f"\nReports Generated:")
        for format_type, path in report_paths.items():
            logger.info(f"  {format_type.upper()}: {path}")
        logger.info("="*80 + "\n")
        
        return scan_result


def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """Configure logging for the pipeline"""
    level = logging.DEBUG if verbose else logging.INFO
    
    # Console handler with custom format
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
