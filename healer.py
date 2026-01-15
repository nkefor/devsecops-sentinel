#!/usr/bin/env python3
"""
DevSecOps Security Sentinel - AI-Powered Infrastructure Security Remediation

This is the main orchestrator that coordinates:
- Multiple security scanners (Checkov, Trivy)
- AI-powered fix generation (Google Gemini)
- Automated PR creation with CIS Benchmark compliance context

Usage:
    python healer.py                    # Run with default settings
    SENTINEL_DRY_RUN=true python healer.py  # Dry run mode
    SENTINEL_SCANNERS=checkov python healer.py  # Use only Checkov
"""

import sys
from typing import List, Dict
from dotenv import load_dotenv

from config import SentinelConfig
from models.vulnerability import Vulnerability, prioritize_vulnerabilities
from scanners import CheckovScanner, TrivyScanner
from ai import GeminiFixer
from vcs import PRCreator


def print_banner():
    """Print the Security Sentinel banner."""
    banner = """
    +===============================================================+
    |         DevSecOps Security Sentinel                           |
    |         AI-Powered Infrastructure Security Remediation        |
    +---------------------------------------------------------------+
    |  Scanners: Checkov + Trivy                                    |
    |  AI Engine: Google Gemini                                     |
    |  Compliance: CIS Benchmarks, SOC 2, PCI-DSS                   |
    +===============================================================+
    """
    print(banner)


def run_scanners(config: SentinelConfig) -> List[Vulnerability]:
    """
    Run all configured scanners and collect vulnerabilities.

    Args:
        config: Sentinel configuration

    Returns:
        List of all discovered vulnerabilities
    """
    all_vulnerabilities: List[Vulnerability] = []

    scanners_map = {
        "checkov": CheckovScanner(config.target_path),
        "trivy": TrivyScanner(config.target_path, config.trivy_scan_type),
    }

    for scanner_name in config.get_enabled_scanners():
        scanner = scanners_map.get(scanner_name)
        if not scanner:
            continue

        if not scanner.is_available():
            print(f"[!] {scanner_name.upper()} is not installed, skipping...")
            continue

        print(f"\n[*] Running {scanner_name.upper()} scanner...")
        vulnerabilities = scanner.scan()
        all_vulnerabilities.extend(vulnerabilities)

    return all_vulnerabilities


def filter_vulnerabilities(
    vulnerabilities: List[Vulnerability],
    config: SentinelConfig
) -> List[Vulnerability]:
    """
    Filter vulnerabilities by severity and prioritize.

    Args:
        vulnerabilities: Raw list of vulnerabilities
        config: Sentinel configuration

    Returns:
        Filtered and prioritized list
    """
    # Filter by severity threshold
    filtered = [
        v for v in vulnerabilities
        if config.should_process(v.severity)
    ]

    # Prioritize (Critical first)
    prioritized = prioritize_vulnerabilities(filtered)

    # Limit to max fixes
    return prioritized[:config.max_fixes]


def process_vulnerability(
    vulnerability: Vulnerability,
    fixer: GeminiFixer,
    pr_creator: PRCreator
) -> Dict:
    """
    Process a single vulnerability: generate fix and create PR.

    Args:
        vulnerability: The vulnerability to fix
        fixer: AI fixer instance
        pr_creator: PR creator instance

    Returns:
        Dictionary with processing results
    """
    result = {
        "check_id": vulnerability.check_id,
        "file": vulnerability.file_path,
        "severity": vulnerability.severity.value,
        "status": "pending",
        "pr_url": None,
        "error": None,
    }

    # Read the file content
    try:
        with open(vulnerability.file_path, 'r') as f:
            file_content = f.read()
    except FileNotFoundError:
        result["status"] = "error"
        result["error"] = f"File not found: {vulnerability.file_path}"
        return result
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        return result

    # Generate fix with AI
    print(f"    [AI] Generating fix for {vulnerability.check_id}...")
    fix_result = fixer.generate_fix(file_content, vulnerability)

    if not fix_result:
        result["status"] = "ai_failed"
        result["error"] = "AI could not generate a fix"
        return result

    fixed_code, explanation = fix_result

    # Generate PR description
    pr_body = fixer.generate_pr_description(vulnerability, explanation)

    # Create PR
    print(f"    [PR] Creating pull request...")
    pr_url = pr_creator.create_fix_pr(vulnerability, fixed_code, pr_body)

    if pr_url:
        result["status"] = "success" if pr_url != "DRY_RUN" else "dry_run"
        result["pr_url"] = pr_url
    else:
        result["status"] = "pr_failed"
        result["error"] = "Failed to create PR"

    return result


def print_summary(results: List[Dict]):
    """Print a summary of all processing results."""
    print("\n" + "=" * 60)
    print("PROCESSING SUMMARY")
    print("=" * 60)

    success = sum(1 for r in results if r["status"] == "success")
    dry_run = sum(1 for r in results if r["status"] == "dry_run")
    failed = sum(1 for r in results if r["status"] not in ["success", "dry_run"])

    print(f"\nTotal processed: {len(results)}")
    print(f"  Successful PRs: {success}")
    print(f"  Dry run: {dry_run}")
    print(f"  Failed: {failed}")

    if results:
        print("\nDetails:")
        for r in results:
            status_icon = {
                "success": "[OK]",
                "dry_run": "[DRY]",
                "error": "[ERR]",
                "ai_failed": "[AI-ERR]",
                "pr_failed": "[PR-ERR]",
            }.get(r["status"], "[?]")

            print(f"  {status_icon} [{r['severity']}] {r['check_id']}")
            if r["pr_url"] and r["pr_url"] != "DRY_RUN":
                print(f"      PR: {r['pr_url']}")
            if r["error"]:
                print(f"      Error: {r['error']}")

    print("=" * 60)


def main():
    """Main entry point for the Security Sentinel."""
    # Load environment variables
    load_dotenv()

    # Print banner
    print_banner()

    # Load configuration
    config = SentinelConfig.from_env()

    # Validate and print warnings
    warnings = config.validate()
    for warning in warnings:
        print(f"[!] Warning: {warning}")

    if config.dry_run:
        print("\n[*] Running in DRY RUN mode - no actual PRs will be created")

    # Initialize components
    fixer = GeminiFixer()
    pr_creator = PRCreator(
        token=config.github_token,
        repo_name=config.repo_name,
        base_branch=config.base_branch
    )

    # Run scanners
    print(f"\n[*] Scanning {config.target_path} for vulnerabilities...")
    vulnerabilities = run_scanners(config)

    if not vulnerabilities:
        print("\n[+] No vulnerabilities found! Your infrastructure is secure.")
        return 0

    print(f"\n[*] Found {len(vulnerabilities)} total vulnerabilities")

    # Filter and prioritize
    to_process = filter_vulnerabilities(vulnerabilities, config)
    print(f"[*] Processing {len(to_process)} vulnerabilities (filtered by severity >= {config.min_severity.value})")

    # Process each vulnerability
    results: List[Dict] = []

    for i, vuln in enumerate(to_process, 1):
        print(f"\n[{i}/{len(to_process)}] Processing {vuln.check_id}")
        print(f"    Severity: {vuln.severity.value}")
        print(f"    File: {vuln.file_path}")
        print(f"    CIS: {vuln.cis_benchmark}")

        result = process_vulnerability(vuln, fixer, pr_creator)
        results.append(result)

    # Print summary
    print_summary(results)

    # Return exit code based on results
    failed_count = sum(1 for r in results if r["status"] not in ["success", "dry_run"])
    return 1 if failed_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
