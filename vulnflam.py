#!/usr/bin/env python3
"""
VulnFlam CLI

Command-line interface for the LLM-enhanced DevSecOps vulnerability pipeline.
This implements the CLI-first approach from Phase 1 of the implementation scope.
"""

import sys
import os
import click
import yaml
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from pipeline import VulnerabilityPipeline, setup_logging
from llm_analyzer import LLMConfig


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    VulnFlam - LLM-Enhanced Vulnerability Assessment

    A production-ready tool for automated security scanning with AI-powered analysis.
    Implements the methodology described in your BSc thesis Chapter 3.
    
    \b
    Quick Start:
      vulnflam scan /path/to/code
      vulnflam scan /path/to/code --llm openai --api-key YOUR_KEY
      vulnflam scan . --no-llm  # Skip LLM analysis
    
    \b
    Configuration:
      Use --config to specify a custom YAML configuration file
      Or set individual options via command-line flags
    """
    pass


@cli.command()
@click.argument('target')
@click.option(
    '--scan-type',
    type=click.Choice(['filesystem', 'container', 'dependencies', 'network']),
    default='filesystem',
    help='Type of scan to perform'
)
@click.option(
    '--llm',
    type=click.Choice(['openai', 'anthropic', 'mock', 'none']),
    default='mock',
    help='LLM provider to use for analysis (default: mock for testing)'
)
@click.option(
    '--api-key',
    envvar='OPENAI_API_KEY',
    help='API key for LLM service (or set OPENAI_API_KEY env var)'
)
@click.option(
    '--model',
    default='gpt-4',
    help='LLM model to use (default: gpt-4)'
)
@click.option(
    '--no-llm',
    is_flag=True,
    help='Skip LLM analysis (faster, but less detailed reports)'
)
@click.option(
    '--format',
    'report_formats',
    multiple=True,
    type=click.Choice(['json', 'markdown', 'html']),
    default=['json', 'markdown', 'html'],
    help='Report format(s) to generate (can specify multiple)'
)
@click.option(
    '--output-dir',
    type=click.Path(),
    default='./reports',
    help='Directory for generated reports'
)
@click.option(
    '--no-parallel',
    is_flag=True,
    help='Run scanners sequentially instead of in parallel'
)
@click.option(
    '--config',
    type=click.Path(exists=True),
    help='Path to YAML configuration file'
)
@click.option(
    '--verbose',
    '-v',
    is_flag=True,
    help='Enable verbose logging'
)
@click.option(
    '--log-file',
    type=click.Path(),
    help='Write logs to file'
)
def scan(
    target,
    scan_type,
    llm,
    api_key,
    model,
    no_llm,
    report_formats,
    output_dir,
    no_parallel,
    config,
    verbose,
    log_file
):
    """
    Scan TARGET for security vulnerabilities.
    
    TARGET can be a directory path, container image, or dependency file.
    
    \b
    Examples:
      # Scan current directory with mock LLM (no API key needed)
      vulnflam scan .
      
      # Scan with OpenAI GPT-4 analysis
      vulnflam scan /path/to/code --llm openai --api-key sk-...
      
      # Quick scan without LLM analysis
      vulnflam scan /path/to/code --no-llm
      
      # Custom output directory and formats
      vulnflam scan . --output-dir ./security-reports --format json --format html
      
      # Use configuration file
      vulnflam scan . --config config.yaml
    """
    # For filesystem/container/dependency scans the target must be a real path
    if scan_type in ('filesystem', 'container', 'dependencies') and not os.path.exists(target):
        click.echo(
            click.style(f"Error: Target path '{target}' does not exist.", fg='red'),
            err=True,
        )
        sys.exit(1)

    # Setup logging
    setup_logging(verbose=verbose, log_file=log_file)
    
    # Load configuration if provided
    config_data = {}
    if config:
        with open(config, 'r') as f:
            config_data = yaml.safe_load(f)
    
    # Determine LLM configuration
    enable_llm = not no_llm
    use_mock_llm = (llm == 'mock' or llm == 'none' or no_llm)
    
    llm_config = None
    if enable_llm and not use_mock_llm:
        if not api_key:
            click.echo(
                click.style(
                    "Error: API key required for LLM analysis. "
                    "Provide --api-key or set OPENAI_API_KEY environment variable. "
                    "Or use --llm mock for testing without API.",
                    fg='red'
                ),
                err=True
            )
            sys.exit(1)
        
        llm_config = LLMConfig(
            api_key=api_key,
            model=model,
            temperature=config_data.get('llm', {}).get('temperature', 0.3),
            max_tokens=config_data.get('llm', {}).get('max_tokens', 1000),
            top_p=config_data.get('llm', {}).get('top_p', 0.9)
        )
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize and run pipeline
    try:
        pipeline = VulnerabilityPipeline(
            llm_config=llm_config,
            use_mock_llm=use_mock_llm,
            output_dir=output_dir
        )
        
        scan_result = pipeline.run(
            target_path=target,
            scan_type=scan_type,
            enable_llm=enable_llm,
            report_formats=list(report_formats),
            parallel_scans=not no_parallel
        )
        
        # Print summary to stdout
        summary = scan_result.get_summary()
        
        click.echo()
        click.secho("✅ Scan Complete!", fg='green', bold=True)
        click.echo()
        click.echo(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        
        if summary['severity_breakdown']['critical'] > 0:
            click.secho(
                f"  Critical: {summary['severity_breakdown']['critical']}",
                fg='red',
                bold=True
            )
        if summary['severity_breakdown']['high'] > 0:
            click.secho(
                f"  High: {summary['severity_breakdown']['high']}",
                fg='yellow'
            )
        click.echo(f"  Medium: {summary['severity_breakdown']['medium']}")
        click.echo(f"  Low: {summary['severity_breakdown']['low']}")
        click.echo(f"  Info: {summary['severity_breakdown']['info']}")
        
        click.echo()
        click.echo(f"Reports generated in: {output_dir}")
        
        # Exit with error code if critical vulnerabilities found
        if summary['severity_breakdown']['critical'] > 0:
            click.secho(
                "\n⚠️  CRITICAL vulnerabilities found! Review immediately.",
                fg='red',
                bold=True
            )
            sys.exit(1)
        
    except Exception as e:
        click.secho(f"\n❌ Pipeline Error: {e}", fg='red', err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
def list_scanners():
    """List available vulnerability scanners on this system."""
    from scanners import ScannerOrchestrator
    
    orchestrator = ScannerOrchestrator()
    available = orchestrator.get_available_scanners()
    
    click.echo("Available Vulnerability Scanners:")
    click.echo()
    
    all_scanners = list(orchestrator.scanners.keys())
    for scanner in all_scanners:
        status = "✓ Available" if scanner in available else "✗ Not installed"
        color = 'green' if scanner in available else 'red'
        click.secho(f"  {scanner:20} {status}", fg=color)
    
    click.echo()
    click.echo(f"Total: {len(available)}/{len(all_scanners)} scanners available")
    
    if len(available) == 0:
        click.echo()
        click.secho(
            "⚠️  No scanners found! Install at least one scanner to use this tool.",
            fg='yellow'
        )
        click.echo()
        click.echo("Installation commands:")
        click.echo("  pip install bandit safety semgrep")
        click.echo("  # For Trivy, see: https://aquasecurity.github.io/trivy/")


@cli.command()
@click.argument('config_file', type=click.Path())
def init_config(config_file):
    """
    Create a sample configuration file.
    
    \b
    Example:
      vulnflam init-config my-config.yaml
    """
    # Read the default config template
    template_path = Path(__file__).parent / 'config' / 'default_config.yaml'
    
    if template_path.exists():
        import shutil
        shutil.copy(template_path, config_file)
        click.secho(f"✓ Created configuration file: {config_file}", fg='green')
        click.echo()
        click.echo("Edit this file to customize scanner and LLM settings.")
    else:
        # Generate a basic config inline
        config = {
            'llm': {
                'provider': 'openai',
                'model': 'gpt-4',
                'api_key': '${OPENAI_API_KEY}',
                'temperature': 0.3,
                'max_tokens': 1000
            },
            'scanners': {
                'bandit': {'enabled': True},
                'trivy': {'enabled': True},
                'safety': {'enabled': True},
                'semgrep': {'enabled': True}
            },
            'reports': {
                'output_dir': './reports',
                'formats': ['json', 'markdown', 'html']
            }
        }
        
        with open(config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        click.secho(f"✓ Created configuration file: {config_file}", fg='green')


if __name__ == '__main__':
    cli()
