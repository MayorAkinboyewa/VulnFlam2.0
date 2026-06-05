#!/usr/bin/env python3
"""
Example usage of the Vulnerability Assessment Pipeline

This script demonstrates various usage patterns.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from pipeline import VulnerabilityPipeline, setup_logging
from llm_analyzer import LLMConfig, MockLLMAnalyzer


def example_basic_scan():
    """Example 1: Basic scan without LLM (fastest)"""
    print("="*80)
    print("EXAMPLE 1: Basic Scan Without LLM")
    print("="*80)
    
    setup_logging(verbose=True)
    
    # Create pipeline with mock LLM
    pipeline = VulnerabilityPipeline(
        use_mock_llm=True,
        output_dir="./reports/example1"
    )
    
    # Run scan
    result = pipeline.run(
        target_path=".",  # Scan current directory
        scan_type="filesystem",
        enable_llm=False,  # No LLM analysis
        report_formats=["json"],  # Just JSON for speed
        parallel_scans=True
    )
    
    print(f"\nFound {len(result.vulnerabilities)} vulnerabilities")
    print(f"Report: ./reports/example1/")


def example_mock_llm_scan():
    """Example 2: Scan with Mock LLM (testing)"""
    print("\n" + "="*80)
    print("EXAMPLE 2: Scan With Mock LLM")
    print("="*80)
    
    setup_logging(verbose=False)
    
    pipeline = VulnerabilityPipeline(
        use_mock_llm=True,
        output_dir="./reports/example2"
    )
    
    result = pipeline.run(
        target_path=".",
        scan_type="filesystem",
        enable_llm=True,  # Use mock LLM
        report_formats=["markdown", "html"],
        parallel_scans=True
    )
    
    print(f"\nGenerated reports:")
    print(f"  Markdown: ./reports/example2/")
    print(f"  HTML: ./reports/example2/")


def example_real_llm_scan():
    """Example 3: Scan with Real LLM (requires API key)"""
    print("\n" + "="*80)
    print("EXAMPLE 3: Scan With Real LLM (OpenAI)")
    print("="*80)
    
    # Check for API key
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("⚠️  OPENAI_API_KEY not set. Skipping this example.")
        print("   Set it with: export OPENAI_API_KEY='sk-...'")
        return
    
    setup_logging(verbose=False)
    
    # Configure LLM
    llm_config = LLMConfig(
        api_key=api_key,
        model="gpt-4",
        temperature=0.3,
        max_tokens=1000
    )
    
    pipeline = VulnerabilityPipeline(
        llm_config=llm_config,
        output_dir="./reports/example3"
    )
    
    result = pipeline.run(
        target_path="./src",  # Scan just the src directory
        scan_type="filesystem",
        enable_llm=True,
        report_formats=["json", "markdown", "html"],
        parallel_scans=True
    )
    
    print(f"\nAnalyzed with GPT-4:")
    for vuln in result.vulnerabilities[:3]:  # Show first 3
        if vuln.llm_explanation:
            print(f"\n{vuln.vulnerability_id}:")
            print(f"  {vuln.llm_explanation[:100]}...")


def example_custom_output():
    """Example 4: Custom output formats and filtering"""
    print("\n" + "="*80)
    print("EXAMPLE 4: Custom Output and Filtering")
    print("="*80)
    
    setup_logging(verbose=False)
    
    pipeline = VulnerabilityPipeline(
        use_mock_llm=True,
        output_dir="./reports/example4"
    )
    
    result = pipeline.run(
        target_path=".",
        scan_type="filesystem",
        enable_llm=True,
        report_formats=["html"],  # Only HTML
        parallel_scans=True
    )
    
    # Filter to show only high severity
    from models import Severity
    high_vulns = [v for v in result.vulnerabilities if v.severity == Severity.HIGH]
    
    print(f"\nTotal vulnerabilities: {len(result.vulnerabilities)}")
    print(f"High severity: {len(high_vulns)}")
    
    if high_vulns:
        print("\nHigh severity findings:")
        for vuln in high_vulns[:5]:
            print(f"  - {vuln.vulnerability_id}: {vuln.title}")


def example_programmatic_usage():
    """Example 5: Using pipeline programmatically"""
    print("\n" + "="*80)
    print("EXAMPLE 5: Programmatic Usage")
    print("="*80)
    
    from pipeline import VulnerabilityPipeline
    from models import Severity
    
    # Setup
    pipeline = VulnerabilityPipeline(use_mock_llm=True, output_dir="./reports/example5")
    
    # Run scan
    result = pipeline.run(
        target_path="./src",
        enable_llm=True,
        report_formats=["json"]
    )
    
    # Process results programmatically
    summary = result.get_summary()
    
    print(f"\nScan Summary:")
    print(f"  Target: {result.target}")
    print(f"  Total: {summary['total_vulnerabilities']}")
    print(f"  Critical: {summary['severity_breakdown']['critical']}")
    print(f"  High: {summary['severity_breakdown']['high']}")
    print(f"  Duration: {result.scan_duration:.2f}s")
    
    # Check for deployment blockers
    critical_count = summary['severity_breakdown']['critical']
    if critical_count > 0:
        print(f"\n❌ DEPLOYMENT BLOCKED: {critical_count} critical vulnerabilities")
        return False
    else:
        print("\n✅ DEPLOYMENT APPROVED: No critical vulnerabilities")
        return True


if __name__ == '__main__':
    print("\nVulnFlam - Usage Examples")
    print("See README.md for full documentation\n")
    
    # Run examples
    try:
        example_basic_scan()
        example_mock_llm_scan()
        example_real_llm_scan()
        example_custom_output()
        example_programmatic_usage()
        
        print("\n" + "="*80)
        print("All examples completed!")
        print("="*80)
        print("\nCheck ./reports/ for generated reports")
        
    except KeyboardInterrupt:
        print("\n\nExamples interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
