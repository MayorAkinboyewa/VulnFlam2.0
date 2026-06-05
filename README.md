# LLM-Enhanced Vulnerability Assessment Pipeline

This is a Python application that orchestrates multiple security scanning tools, processes their outputs intelligently, and generates actionable developer reports using LLM-powered analysis.

This implementation follows the methodology described in Chapter Three of the BSc project: "An LLM-Driven Approach to Automated Vulnerability Analysis"

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Chapter 3 Methodology Alignment](#chapter-3-methodology-alignment)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## 🎯 Overview

This tool implements a complete vulnerability assessment pipeline that:

1. **Executes multiple vulnerability scanners** (Bandit, Trivy, Safety, Semgrep)
2. **Parses heterogeneous outputs** into a unified data model
3. **Enhances findings with LLM analysis** for contextual understanding
4. **Generates developer-ready reports** in JSON, Markdown, and HTML formats

The pipeline is designed for **resource-constrained environments** and supports both API-based LLMs (OpenAI, Anthropic) and mock analysis for testing.

## 🏗️ Architecture

The pipeline follows a 4-layer architecture (Chapter 3, Section 3.2.2):

```
┌─────────────────────────────────────────────────────────────┐
│                     SCANNER LAYER                           │
│  Bandit │ Trivy │ Safety │ Semgrep | Nikto | Nmap           │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    PROCESSING LAYER                         │
│  Parser → Normalization → Prompt Construction               │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  LLM ANALYSIS LAYER                         │
│  Chain-of-Thought Prompting → LLM API → Structured Output   │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   REPORTING LAYER                           │
│  JSON (CI/CD) │ Markdown (VCS) │ HTML (Review)              │
└─────────────────────────────────────────────────────────────┘
```

## ✨ Features

### Security Scanning

- ✅ **Multi-tool integration**: Bandit (Python SAST), Trivy (containers/dependencies), Safety (Python deps), Semgrep (multi-language SAST)
- ✅ **Parallel execution**: Run scanners concurrently for faster results
- ✅ **Graceful degradation**: Continue if some scanners unavailable
- ✅ **Deduplication**: Intelligent merging of findings across tools

### LLM Enhancement

- ✅ **Contextual analysis**: Chain-of-thought prompting for deep understanding
- ✅ **Severity validation**: AI-powered assessment of true risk
- ✅ **Exploitability analysis**: Realistic attack scenario generation
- ✅ **Remediation guidance**: Step-by-step fix instructions with code examples
- ✅ **Multiple providers**: OpenAI (GPT-4, GPT-3.5), Anthropic (Claude), or Mock for testing

### Report Generation

- ✅ **JSON**: Machine-readable for CI/CD automation
- ✅ **Markdown**: VCS-friendly, commit with your code
- ✅ **HTML**: Interactive reports with collapsible sections and syntax highlighting
- ✅ **Developer-focused**: Clear explanations, not just CVE IDs

### Operational

- ✅ **CLI-first design**: Fully scriptable for CI/CD integration
- ✅ **Configuration via YAML or flags**: Flexible deployment options
- ✅ **Comprehensive logging**: Debug and audit trail
- ✅ **Error handling**: Robust parsing and retry logic
- ✅ **Resource-conscious**: Designed for environments without GPUs or extensive infrastructure

## 🚀 Installation

### Prerequisites

- Python 3.10 or higher
- At least one vulnerability scanner installed

### Step 1: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Install Vulnerability Scanners

```bash
# Bandit (Python SAST)
pip install bandit

# Safety (Python dependency checker)
pip install safety

# Semgrep (Multi-language SAST)
pip install semgrep

# Trivy (Container/filesystem scanner)
# Install from https://aquasecurity.github.io/trivy/
# Ubuntu/Debian:
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

### Step 3: Verify Installation

```bash
python vulnflam.py list-scanners
```

You should see which scanners are available.

## ⚡ Quick Start

### Basic Scan (No LLM, Fast)

```bash
# Scan current directory without LLM analysis
python vulnflam.py scan . --no-llm
```

### Scan with Mock LLM (Testing)

```bash
# Use mock LLM for testing (no API key needed)
python vulnflam.py scan /path/to/code --llm mock
```

### Scan with OpenAI GPT-4

```bash
# Set API key as environment variable
export OPENAI_API_KEY="sk-your-key-here"

# Run scan with LLM analysis
python vulnflam.py scan /path/to/code --llm openai --model gpt-4
```

### Quick Scan with Custom Output

```bash
python vulnflam.py scan . \
  --llm mock \
  --format json \
  --format html \
  --output-dir ./security-reports
```

## 📖 Usage

### Command Overview

```bash
# List available commands
python vulnflam.py --help

# Scan a target
python vulnflam.py scan [OPTIONS] TARGET

# List available scanners
python vulnflam.py list-scanners

# Create configuration file
python vulnflam.py init-config config.yaml
```

### Scan Command Options

```
Usage: vulnflam.py scan [OPTIONS] TARGET

Options:
  --scan-type [filesystem|container|dependencies]
                                  Type of scan to perform
  --llm [openai|anthropic|mock|none]
                                  LLM provider (default: mock)
  --api-key TEXT                  API key for LLM service
  --model TEXT                    LLM model to use (default: gpt-4)
  --no-llm                        Skip LLM analysis
  --format [json|markdown|html]   Report format(s) (can specify multiple)
  --output-dir PATH               Directory for generated reports
  --no-parallel                   Run scanners sequentially
  --config PATH                   Path to YAML configuration file
  --verbose, -v                   Enable verbose logging
  --log-file PATH                 Write logs to file
  --help                          Show this message and exit
```

### Examples

#### 1. Development Workflow

```bash
# Quick scan during development (fast, no LLM)
python vulnflam.py scan . --no-llm --format json

# Detailed scan before commit
python vulnflam.py scan . --llm mock --format markdown
```

#### 2. CI/CD Integration

```bash
#!/bin/bash
# ci-security-scan.sh

# Exit on critical vulnerabilities
python vulnflam.py scan . \
  --llm openai \
  --api-key ${OPENAI_API_KEY} \
  --format json \
  --output-dir ./security-reports

# Check exit code
if [ $? -ne 0 ]; then
  echo "Critical vulnerabilities found! Failing build."
  exit 1
fi
```

#### 3. Container Scanning

```bash
# Scan a Docker image
python vulnflam.py scan nginx:latest \
  --scan-type container \
  --llm openai \
  --format html
```

#### 4. Using Configuration File

```bash
# Create config
python vulnflam.py init-config my-config.yaml

# Edit my-config.yaml to set preferences

# Run with config
python vulnflam.py scan . --config my-config.yaml
```

## ⚙️ Configuration

### YAML Configuration File

```yaml
# config.yaml
llm:
  provider: openai
  model: gpt-4
  api_key: ${OPENAI_API_KEY}  # Use environment variable
  temperature: 0.3
  max_tokens: 1000

scanners:
  bandit:
    enabled: true
  trivy:
    enabled: true
  safety:
    enabled: true
  semgrep:
    enabled: true

scan:
  parallel: true
  max_workers: 4

reports:
  output_dir: ./reports
  formats:
    - json
    - markdown
    - html
```

### Environment Variables

```bash
# LLM API Keys
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

# Logging
export VULNFLAM_LOG_LEVEL="DEBUG"
export VULNFLAM_LOG_FILE="./pipeline.log"
```

## 📊 Output Formats

### JSON (Machine-Readable)

```json
{
  "target": "/path/to/code",
  "scan_type": "filesystem",
  "tools_used": ["bandit", "trivy"],
  "vulnerabilities": [
    {
      "vulnerability_id": "CVE-2023-12345",
      "severity": "High",
      "affected_component": "package-name",
      "llm_explanation": "...",
      "llm_remediation_steps": ["...", "..."]
    }
  ],
  "summary": {
    "total_vulnerabilities": 15,
    "severity_breakdown": {
      "critical": 2,
      "high": 5,
      "medium": 6,
      "low": 2
    }
  }
}
```

### Markdown (VCS-Friendly)

```markdown
# Vulnerability Assessment Report

**Target**: /path/to/code
**Generated**: 2025-05-16T10:30:00

## Executive Summary

Total Vulnerabilities Found: 15

### Severity Breakdown
- **Critical**: 2
- **High**: 5
- **Medium**: 6
- **Low**: 2

## ⚠️ Critical Findings

### CVE-2023-12345: SQL Injection in User Input

**Severity**: Critical
**Component**: `user_auth.py:45`

**Analysis**:
This vulnerability allows an attacker to inject arbitrary SQL...

**Remediation Steps**:
1. Use parameterized queries instead of string concatenation
2. Implement input validation...
```

### HTML (Interactive Review)

- ✅ Color-coded severity badges
- ✅ Collapsible vulnerability cards
- ✅ Syntax-highlighted code examples
- ✅ Interactive navigation
- ✅ Print-friendly layout

## 🎓 Chapter 3 Methodology Alignment

This implementation directly follows the methodology described in Chapter 3:

| Chapter Section | Implementation Component |
|----------------|--------------------------|
| 3.2.2 - Scanner Layer | `scanners.py`: ScannerOrchestrator |
| 3.2.2 - Processing Layer | `parsers.py`: ParserFactory, Normalization |
| 3.2.2 - LLM Analysis Layer | `llm_analyzer.py`: PromptConstructor, LLMAnalyzer |
| 3.2.2 - Reporting Layer | `reports.py`: ReportGenerator |
| 3.2.3 - Data Flow | `pipeline.py`: VulnerabilityPipeline |
| 3.3.1 - Scanning Tools | Bandit, Trivy, Safety, Semgrep integration |
| 3.4.2 - Prompt Engineering | Chain-of-thought, contextual enrichment |
| 3.4.4 - LLM Configuration | Temperature 0.3, top-p 0.9, structured output |
| 3.5 - Report Formats | JSON, Markdown, HTML generation |

### Data Model

The unified `Vulnerability` data structure (Chapter 3, Section 3.2.2) captures:

- ✅ Core identification (tool, ID, title, description)
- ✅ Severity assessment (severity, CVSS score, vector)
- ✅ Location information (component, version, file path, line number)
- ✅ Classification (vulnerability type, CWE ID)
- ✅ LLM enhancement fields (validation, explanation, remediation)

## 🐛 Troubleshooting

### No Scanners Available

```bash
# Check which scanners are installed
python vulnflam.py list-scanners

# Install missing scanners
pip install bandit safety semgrep
```

### LLM API Errors

```bash
# Verify API key
echo $OPENAI_API_KEY

# Use mock LLM for testing
python vulnflam.py scan . --llm mock

# Check API quota/rate limits
```

### Permission Errors

```bash
# Ensure target path is readable
ls -la /path/to/code

# Ensure output directory is writable
mkdir -p ./reports
chmod 755 ./reports
```

### Parsing Errors

```bash
# Run with verbose logging
python vulnflam.py scan . --verbose --log-file debug.log

# Check log file for detailed error messages
cat debug.log
```

## 👩‍💻 Development

### Project Structure

```
vulnflam/
├── src/
│   ├── models.py           # Data models (Vulnerability, ScanResult)
│   ├── scanners.py         # Scanner orchestration
│   ├── parsers.py          # Output parsing and normalization
│   ├── llm_analyzer.py     # LLM integration and prompt construction
│   ├── reports.py          # Report generation (JSON, MD, HTML)
│   └── pipeline.py         # Main pipeline orchestrator
├── config/
│   └── default_config.yaml # Default configuration template
├── tests/                  # Unit tests (TODO)
├── reports/                # Generated reports (created at runtime)
├── requirements.txt        # Python dependencies
├── vulnflam.py             # CLI entry point
└── README.md               # This file
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/

# With coverage
pytest tests/ --cov=src --cov-report=html
```

### Adding New Scanners

1. Add scanner config to `scanners.py`:

```python
self.scanners['newscan'] = ScannerConfig(
    name='newscan',
    command='newscan',
    output_format='json'
)
```

1. Create parser in `parsers.py`:

```python
class NewScanParser(VulnerabilityParser):
    def parse(self, output_file: str) -> List[Vulnerability]:
        # Parse newscan output
        ...
```

1. Register parser:

```python
ParserFactory.PARSERS['newscan'] = NewScanParser
```

## 📝 License

This project is part of a BSc project and is provided for educational and research purposes.

## 👤 Author

**Akinboyewa Mayowa Akintomide** (EU220102-3129)  
BSc Cyber Security  
Elizade University, Ilara-Mokin

**Supervisor**: Dr. Folasade Aliu

## 🙏 Acknowledgments

- Chapter 3 methodology design based on Design Science Research principles (Hevner et al., 2004)
- LLM integration inspired by recent research on AI-enhanced DevSecOps (Fu et al., 2025)
- Prompt engineering techniques from Nong et al. (2024) on chain-of-thought for vulnerability analysis

## 📚 References

See the full project document for comprehensive references to:

- Design Science Research methodology
- LLM-enhanced vulnerability detection literature
- DevSecOps pipeline integration studies
- Prompt engineering techniques for security
