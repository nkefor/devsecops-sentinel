"""Checkov scanner implementation for infrastructure security scanning."""
import json
import subprocess
import shutil
from typing import List, Optional, Dict, Any
from models.vulnerability import Vulnerability, Severity
from .base_scanner import BaseScanner


class CheckovScanner(BaseScanner):
    """Checkov-based infrastructure security scanner."""

    def __init__(self, target_path: str = "."):
        """Initialize Checkov scanner."""
        super().__init__(target_path)
        self.name = "checkov"

    def is_available(self) -> bool:
        """Check if Checkov is installed (CLI or Python module)."""
        # First check CLI
        if shutil.which("checkov") is not None:
            return True
        # Then check if available as Python module
        try:
            import checkov
            return True
        except ImportError:
            return False

    def _get_checkov_command(self) -> List[str]:
        """Get the appropriate command to run checkov."""
        if shutil.which("checkov") is not None:
            return ['checkov']
        # Use Python module
        import sys
        return [sys.executable, '-m', 'checkov.main']

    def scan(self) -> List[Vulnerability]:
        """
        Run Checkov scan and return vulnerabilities.

        Returns:
            List of Vulnerability objects
        """
        print(f"[Checkov] Scanning {self.target_path}...")

        if not self.is_available():
            print("[Checkov] ERROR: Checkov is not installed. Run: pip install checkov")
            return []

        try:
            cmd = self._get_checkov_command() + [
                '-d', self.target_path,
                '-o', 'json',
                '--quiet',
                '--compact'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False  # Checkov returns non-zero when issues found
            )

            if not result.stdout.strip():
                if result.stderr:
                    print(f"[Checkov] stderr: {result.stderr[:200]}")
                print("[Checkov] No output received")
                return []

            return self._parse_results(result.stdout)

        except Exception as e:
            print(f"[Checkov] Error running scan: {e}")
            return []

    def _parse_results(self, json_output: str) -> List[Vulnerability]:
        """
        Parse Checkov JSON output into Vulnerability objects.

        Args:
            json_output: Raw JSON string from Checkov

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []

        try:
            report = json.loads(json_output)

            # Handle different output formats (single result vs list)
            results = report if isinstance(report, list) else [report]

            for check_type in results:
                failed_checks = check_type.get('results', {}).get('failed_checks', [])

                for check in failed_checks:
                    vuln = self._create_vulnerability(check)
                    if vuln:
                        vulnerabilities.append(vuln)

        except json.JSONDecodeError as e:
            print(f"[Checkov] Error parsing JSON output: {e}")

        print(f"[Checkov] Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    def _create_vulnerability(self, check: Dict[str, Any]) -> Optional[Vulnerability]:
        """
        Create a Vulnerability object from a Checkov check result.

        Args:
            check: Dictionary containing Checkov check data

        Returns:
            Vulnerability object or None if parsing fails
        """
        try:
            # Map Checkov severity to our Severity enum
            checkov_severity = check.get('severity', 'MEDIUM')
            if checkov_severity:
                severity = Severity.from_string(checkov_severity)
            else:
                # Default based on check type
                severity = self._infer_severity(check.get('check_id', ''))

            # Clean up file path (remove leading slashes for both Unix and Windows)
            file_path = check.get('file_path', '').lstrip('/').lstrip('\\')

            return Vulnerability(
                check_id=check.get('check_id', 'UNKNOWN'),
                check_name=check.get('check_name', 'Unknown check'),
                file_path=file_path,
                severity=severity,
                scanner=self.name,
                resource=check.get('resource', ''),
                line_start=check.get('file_line_range', [0, 0])[0],
                line_end=check.get('file_line_range', [0, 0])[1],
                guideline=check.get('guideline', ''),
            )
        except Exception as e:
            print(f"[Checkov] Error creating vulnerability: {e}")
            return None

    def _infer_severity(self, check_id: str) -> Severity:
        """
        Infer severity from check ID patterns.

        Args:
            check_id: The Checkov check ID

        Returns:
            Inferred Severity level
        """
        # Critical patterns (wide-open access, secrets)
        critical_patterns = ['CKV_SECRET', 'CKV_AWS_23', 'CKV_AWS_24', 'CKV_AWS_25']
        if any(p in check_id for p in critical_patterns):
            return Severity.CRITICAL

        # High patterns (encryption, public access)
        high_patterns = ['CKV_AWS_16', 'CKV_AWS_17', 'CKV_AWS_19', 'CKV_AWS_20', 'CKV2_AWS_6']
        if any(p in check_id for p in high_patterns):
            return Severity.HIGH

        # Default to medium
        return Severity.MEDIUM
