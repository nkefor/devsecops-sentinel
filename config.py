"""Configuration management for DevSecOps Sentinel."""
import os
from dataclasses import dataclass, field
from typing import List, Optional
from models.vulnerability import Severity


@dataclass
class SentinelConfig:
    """
    Configuration settings for the Security Sentinel.

    Attributes:
        target_path: Directory to scan for vulnerabilities
        scanners: List of scanners to use ('checkov', 'trivy', or both)
        min_severity: Minimum severity level to process
        max_fixes: Maximum number of fixes to generate per run
        dry_run: If True, don't create actual PRs
        base_branch: Base branch for PRs
        trivy_scan_type: Type of Trivy scan ('config', 'fs', 'image')
    """

    # Scanning settings
    target_path: str = "."
    scanners: List[str] = field(default_factory=lambda: ["checkov", "trivy"])
    min_severity: Severity = Severity.LOW
    max_fixes: int = 10

    # GitHub settings
    dry_run: bool = False
    base_branch: str = "main"

    # Trivy-specific settings
    trivy_scan_type: str = "config"

    # API keys (loaded from environment)
    github_token: Optional[str] = field(default=None, repr=False)
    gemini_api_key: Optional[str] = field(default=None, repr=False)
    repo_name: Optional[str] = None

    def __post_init__(self):
        """Load configuration from environment variables."""
        self.github_token = self.github_token or os.getenv("GITHUB_TOKEN")
        self.gemini_api_key = self.gemini_api_key or os.getenv("GEMINI_API_KEY")
        self.repo_name = self.repo_name or os.getenv("GITHUB_REPOSITORY")

        # Enable dry run if GitHub credentials are missing
        if not self.github_token or not self.repo_name:
            self.dry_run = True

    @classmethod
    def from_env(cls) -> 'SentinelConfig':
        """
        Create configuration from environment variables.

        Environment variables:
            SENTINEL_TARGET_PATH: Directory to scan (default: ".")
            SENTINEL_SCANNERS: Comma-separated scanners (default: "checkov,trivy")
            SENTINEL_MIN_SEVERITY: Minimum severity (default: "LOW")
            SENTINEL_MAX_FIXES: Maximum fixes per run (default: 10)
            SENTINEL_DRY_RUN: Enable dry run mode (default: false)
            SENTINEL_BASE_BRANCH: Base branch for PRs (default: "main")
            SENTINEL_TRIVY_SCAN_TYPE: Trivy scan type (default: "config")
            GITHUB_TOKEN: GitHub access token
            GEMINI_API_KEY: Google Gemini API key
            GITHUB_REPOSITORY: Repository in format "owner/repo"

        Returns:
            Configured SentinelConfig instance
        """
        # Parse scanners
        scanners_str = os.getenv("SENTINEL_SCANNERS", "checkov,trivy")
        scanners = [s.strip().lower() for s in scanners_str.split(",")]

        # Parse severity
        severity_str = os.getenv("SENTINEL_MIN_SEVERITY", "LOW").upper()
        min_severity = Severity.from_string(severity_str)

        # Parse dry run
        dry_run_str = os.getenv("SENTINEL_DRY_RUN", "false").lower()
        dry_run = dry_run_str in ("true", "1", "yes")

        return cls(
            target_path=os.getenv("SENTINEL_TARGET_PATH", "."),
            scanners=scanners,
            min_severity=min_severity,
            max_fixes=int(os.getenv("SENTINEL_MAX_FIXES", "10")),
            dry_run=dry_run,
            base_branch=os.getenv("SENTINEL_BASE_BRANCH", "main"),
            trivy_scan_type=os.getenv("SENTINEL_TRIVY_SCAN_TYPE", "config"),
        )

    def should_process(self, severity: Severity) -> bool:
        """
        Check if a vulnerability with given severity should be processed.

        Args:
            severity: The vulnerability severity

        Returns:
            True if severity meets minimum threshold
        """
        return severity.priority <= self.min_severity.priority

    def get_enabled_scanners(self) -> List[str]:
        """Get list of enabled scanners."""
        valid_scanners = ["checkov", "trivy"]
        return [s for s in self.scanners if s in valid_scanners]

    def validate(self) -> List[str]:
        """
        Validate configuration and return list of warnings.

        Returns:
            List of warning messages
        """
        warnings = []

        if not self.gemini_api_key:
            warnings.append("GEMINI_API_KEY not set - AI-powered fixes will be disabled")

        if not self.github_token:
            warnings.append("GITHUB_TOKEN not set - PR creation will be disabled (dry-run mode)")

        if not self.repo_name:
            warnings.append("GITHUB_REPOSITORY not set - PR creation will be disabled (dry-run mode)")

        if not self.scanners:
            warnings.append("No scanners configured - no vulnerabilities will be found")

        return warnings
