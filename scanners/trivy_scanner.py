"""Trivy scanner implementation for infrastructure and container security scanning."""
import json
import subprocess
import shutil
from typing import List, Optional, Dict, Any
from models.vulnerability import Vulnerability, Severity
from .base_scanner import BaseScanner


class TrivyScanner(BaseScanner):
    """Trivy-based security scanner for filesystem and container scanning."""

    def __init__(self, target_path: str = ".", scan_type: str = "config"):
        """
        Initialize Trivy scanner.

        Args:
            target_path: Path to scan
            scan_type: Type of scan - 'config' for IaC, 'fs' for filesystem, 'image' for containers
        """
        super().__init__(target_path)
        self.name = "trivy"
        self.scan_type = scan_type

    def is_available(self) -> bool:
        """Check if Trivy is installed."""
        return shutil.which("trivy") is not None

    def scan(self) -> List[Vulnerability]:
        """
        Run Trivy scan and return vulnerabilities.

        Returns:
            List of Vulnerability objects
        """
        print(f"[Trivy] Scanning {self.target_path} (type: {self.scan_type})...")

        if not self.is_available():
            print("[Trivy] ERROR: Trivy is not installed.")
            print("[Trivy] Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
            return []

        try:
            # Build command based on scan type
            cmd = self._build_command()

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )

            if not result.stdout.strip():
                if result.stderr:
                    print(f"[Trivy] Warning: {result.stderr[:200]}")
                print("[Trivy] No vulnerabilities found or no output received")
                return []

            return self._parse_results(result.stdout)

        except Exception as e:
            print(f"[Trivy] Error running scan: {e}")
            return []

    def _build_command(self) -> List[str]:
        """Build the Trivy command based on scan type."""
        base_cmd = ['trivy']

        if self.scan_type == "config":
            # Scan for IaC misconfigurations (Terraform, CloudFormation, etc.)
            return base_cmd + [
                'config',
                '--format', 'json',
                '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                self.target_path
            ]
        elif self.scan_type == "fs":
            # Filesystem vulnerability scan
            return base_cmd + [
                'fs',
                '--format', 'json',
                '--scanners', 'vuln,misconfig,secret',
                self.target_path
            ]
        elif self.scan_type == "image":
            # Container image scan
            return base_cmd + [
                'image',
                '--format', 'json',
                self.target_path
            ]
        else:
            # Default to config scan
            return base_cmd + ['config', '--format', 'json', self.target_path]

    def _parse_results(self, json_output: str) -> List[Vulnerability]:
        """
        Parse Trivy JSON output into Vulnerability objects.

        Args:
            json_output: Raw JSON string from Trivy

        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []

        try:
            report = json.loads(json_output)

            # Trivy output structure varies by scan type
            # For config scans, results are in 'Results' array
            results = report.get('Results', [])

            for result in results:
                target = result.get('Target', '')

                # Process misconfigurations
                misconfigs = result.get('Misconfigurations', [])
                for misconfig in misconfigs:
                    vuln = self._create_vulnerability_from_misconfig(misconfig, target)
                    if vuln:
                        vulnerabilities.append(vuln)

                # Process vulnerabilities (for fs/image scans)
                vulns = result.get('Vulnerabilities', [])
                for vuln_data in vulns:
                    vuln = self._create_vulnerability_from_vuln(vuln_data, target)
                    if vuln:
                        vulnerabilities.append(vuln)

                # Process secrets
                secrets = result.get('Secrets', [])
                for secret in secrets:
                    vuln = self._create_vulnerability_from_secret(secret, target)
                    if vuln:
                        vulnerabilities.append(vuln)

        except json.JSONDecodeError as e:
            print(f"[Trivy] Error parsing JSON output: {e}")

        print(f"[Trivy] Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    def _create_vulnerability_from_misconfig(
        self,
        misconfig: Dict[str, Any],
        target: str
    ) -> Optional[Vulnerability]:
        """Create Vulnerability from Trivy misconfiguration result."""
        try:
            severity = Severity.from_string(misconfig.get('Severity', 'MEDIUM'))

            # Extract cause location if available
            cause = misconfig.get('CauseMetadata', {})
            start_line = cause.get('StartLine', 0)
            end_line = cause.get('EndLine', start_line)

            return Vulnerability(
                check_id=misconfig.get('AVDID', misconfig.get('ID', 'UNKNOWN')),
                check_name=misconfig.get('Title', 'Unknown issue'),
                file_path=target,
                severity=severity,
                scanner=self.name,
                resource=cause.get('Resource', ''),
                line_start=start_line,
                line_end=end_line,
                guideline=misconfig.get('PrimaryURL', ''),
            )
        except Exception as e:
            print(f"[Trivy] Error creating vulnerability from misconfig: {e}")
            return None

    def _create_vulnerability_from_vuln(
        self,
        vuln_data: Dict[str, Any],
        target: str
    ) -> Optional[Vulnerability]:
        """Create Vulnerability from Trivy vulnerability result."""
        try:
            severity = Severity.from_string(vuln_data.get('Severity', 'MEDIUM'))

            return Vulnerability(
                check_id=vuln_data.get('VulnerabilityID', 'UNKNOWN'),
                check_name=vuln_data.get('Title', vuln_data.get('Description', 'Unknown vulnerability')[:100]),
                file_path=target,
                severity=severity,
                scanner=self.name,
                resource=vuln_data.get('PkgName', ''),
                guideline=vuln_data.get('PrimaryURL', ''),
            )
        except Exception as e:
            print(f"[Trivy] Error creating vulnerability from vuln: {e}")
            return None

    def _create_vulnerability_from_secret(
        self,
        secret: Dict[str, Any],
        target: str
    ) -> Optional[Vulnerability]:
        """Create Vulnerability from Trivy secret finding."""
        try:
            return Vulnerability(
                check_id="SECRET_DETECTED",
                check_name=f"Secret detected: {secret.get('Title', 'Unknown secret')}",
                file_path=target,
                severity=Severity.CRITICAL,
                scanner=self.name,
                resource=secret.get('Category', ''),
                line_start=secret.get('StartLine', 0),
                line_end=secret.get('EndLine', 0),
                guideline="Secrets should never be committed to version control",
            )
        except Exception as e:
            print(f"[Trivy] Error creating vulnerability from secret: {e}")
            return None
