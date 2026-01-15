# DevSecOps Security Sentinel

**AI-Powered Infrastructure Security Remediation**

Automatically scan your Terraform infrastructure for security vulnerabilities and generate Pull Requests with fixes using AI. The Security Sentinel integrates into your CI/CD pipeline to provide continuous security compliance.

## Features

- **Multi-Scanner Support**: Combines Checkov and Trivy for comprehensive vulnerability detection
- **AI-Powered Fixes**: Uses Google Gemini to automatically generate secure code fixes
- **CIS Benchmark Compliance**: Maps vulnerabilities to CIS AWS Foundations, SOC 2, and PCI-DSS controls
- **Automated PR Creation**: Creates detailed Pull Requests with risk assessments and remediation explanations
- **Severity Prioritization**: Processes critical vulnerabilities first (Critical > High > Medium > Low)
- **Configurable**: Environment variables for scanners, severity thresholds, and more

## Architecture

```
+------------------+     +------------------+     +------------------+
|    Scanners      |     |    AI Engine     |     |   VCS Integration|
|------------------|     |------------------|     |------------------|
| - Checkov        |---->| - Google Gemini  |---->| - GitHub API     |
| - Trivy          |     | - CIS Mappings   |     | - PR Creation    |
+------------------+     +------------------+     +------------------+
         |                        |                        |
         v                        v                        v
+------------------------------------------------------------------+
|                    Vulnerability Model                            |
|------------------------------------------------------------------|
| - Severity Classification    - Compliance Mappings               |
| - File Location              - Remediation Context               |
+------------------------------------------------------------------+
```

## Project Structure

```
devsecops-sentinel/
├── healer.py                 # Main orchestrator
├── config.py                 # Configuration management
├── requirements.txt          # Python dependencies
├── models/
│   ├── __init__.py
│   └── vulnerability.py      # Vulnerability model with CIS mappings
├── scanners/
│   ├── __init__.py
│   ├── base_scanner.py       # Abstract scanner interface
│   ├── checkov_scanner.py    # Checkov implementation
│   └── trivy_scanner.py      # Trivy implementation
├── ai/
│   ├── __init__.py
│   └── gemini_fixer.py       # AI-powered fix generation
├── vcs/
│   ├── __init__.py
│   └── pr_creator.py         # GitHub PR creation
└── .github/workflows/
    └── sentinel.yml          # GitHub Actions workflow
```

## Quick Start

### Prerequisites

- Python 3.10+
- [Checkov](https://www.checkov.io/) (`pip install checkov`)
- [Trivy](https://aquasecurity.github.io/trivy/) (optional, for container scanning)
- Google Gemini API key
- GitHub personal access token (for PR creation)

### Installation

```bash
# Clone the repository
git clone https://github.com/nkefor/devsecops-sentinel.git
cd devsecops-sentinel

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file or set environment variables:

```bash
# Required for AI fixes
GEMINI_API_KEY=your-gemini-api-key

# Required for PR creation
GITHUB_TOKEN=your-github-token
GITHUB_REPOSITORY=owner/repo

# Optional settings
SENTINEL_SCANNERS=checkov,trivy    # Scanners to use
SENTINEL_MIN_SEVERITY=LOW          # Minimum severity (CRITICAL, HIGH, MEDIUM, LOW)
SENTINEL_MAX_FIXES=10              # Maximum fixes per run
SENTINEL_DRY_RUN=false             # Set to true for testing
SENTINEL_BASE_BRANCH=main          # Base branch for PRs
```

### Usage

```bash
# Run with default settings
python healer.py

# Dry run mode (no PRs created)
SENTINEL_DRY_RUN=true python healer.py

# Use only Checkov scanner
SENTINEL_SCANNERS=checkov python healer.py

# Process only critical and high severity issues
SENTINEL_MIN_SEVERITY=HIGH python healer.py
```

## GitHub Actions Integration

The workflow runs automatically on push/PR to main branch, or can be triggered manually.

### Setup

1. Go to your repository **Settings** → **Secrets and variables** → **Actions**
2. Add the following secrets:
   - `GEMINI_API_KEY`: Your Google Gemini API key

### Manual Trigger

1. Go to **Actions** tab
2. Select **Security Sentinel** workflow
3. Click **Run workflow**
4. Configure options:
   - Scanners to use
   - Minimum severity
   - Maximum fixes
   - Dry run mode

## Example Output

```
+===============================================================+
|         DevSecOps Security Sentinel                           |
|         AI-Powered Infrastructure Security Remediation        |
+---------------------------------------------------------------+
|  Scanners: Checkov + Trivy                                    |
|  AI Engine: Google Gemini                                     |
|  Compliance: CIS Benchmarks, SOC 2, PCI-DSS                   |
+===============================================================+

[*] Scanning . for vulnerabilities...
[*] Running CHECKOV scanner...
[Checkov] Found 17 vulnerabilities

[*] Found 17 total vulnerabilities
[*] Processing 10 vulnerabilities (filtered by severity >= LOW)

[1/10] Processing CKV_AWS_23
    Severity: CRITICAL
    File: vulnerable_infrastructure.tf
    CIS: CIS AWS 5.2
    [AI] Generating fix for CKV_AWS_23...
    [PR] Creating pull request...
    PR Created: https://github.com/owner/repo/pull/1
```

## PR Description Example

When a vulnerability is fixed, the sentinel creates a detailed PR:

```markdown
## Security Vulnerability Fix

**Vulnerability ID:** `CKV_AWS_23`
**Severity:** CRITICAL
**Scanner:** CHECKOV
**File:** `main.tf`

### Description
Ensure no security groups allow ingress from 0.0.0.0/0 to port 22

### Risk Assessment
This vulnerability was identified as CRITICAL severity because it could potentially:
- Expose infrastructure to unauthorized access
- Violate compliance requirements

### Compliance Impact
| Framework | Control | Status |
|-----------|---------|--------|
| CIS AWS Foundations | CIS AWS 5.2 | Remediated |
| SOC 2 | CC6.1, CC6.6 | Remediated |
| PCI-DSS | 1.2.1, 1.3.1 | Remediated |
```

## Supported Vulnerability Types

| Category | Check IDs | CIS Benchmark |
|----------|-----------|---------------|
| Security Groups | CKV_AWS_23, CKV_AWS_24, CKV_AWS_25 | CIS AWS 5.2-5.4 |
| S3 Buckets | CKV_AWS_18-21, CKV2_AWS_6 | CIS AWS 2.1.x |
| RDS Databases | CKV_AWS_16, CKV_AWS_17, CKV_AWS_157 | CIS AWS 2.3.x |
| IAM Policies | CKV_AWS_1, CKV_AWS_40 | CIS AWS 1.x |
| Encryption | CKV_AWS_7 | CIS AWS 2.8 |
| CloudTrail | CKV_AWS_35 | CIS AWS 3.1 |

## Extending the Sentinel

### Adding a New Scanner

1. Create a new file in `scanners/` extending `BaseScanner`
2. Implement `is_available()` and `scan()` methods
3. Register the scanner in `healer.py`

```python
from scanners.base_scanner import BaseScanner

class CustomScanner(BaseScanner):
    def __init__(self, target_path: str = "."):
        super().__init__(target_path)
        self.name = "custom"

    def is_available(self) -> bool:
        # Check if scanner is installed
        return True

    def scan(self) -> List[Vulnerability]:
        # Run scan and return vulnerabilities
        return []
```

### Adding CIS Benchmark Mappings

Edit `models/vulnerability.py` and add entries to `CIS_BENCHMARK_MAP`:

```python
CIS_BENCHMARK_MAP = {
    "NEW_CHECK_ID": {
        "cis_id": "CIS AWS X.X",
        "title": "Description of the requirement",
        "soc2": "CC6.1",
        "pci_dss": "1.2.3"
    },
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Checkov](https://www.checkov.io/) - Infrastructure as Code security scanning
- [Trivy](https://aquasecurity.github.io/trivy/) - Comprehensive vulnerability scanner
- [Google Gemini](https://ai.google.dev/) - AI-powered code generation
