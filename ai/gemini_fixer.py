"""AI-powered code fixer using Google Gemini with CIS Benchmark awareness."""
import os
from typing import Optional, Tuple
from tenacity import retry, stop_after_attempt, wait_exponential
import google.generativeai as genai
from models.vulnerability import Vulnerability


class GeminiFixer:
    """
    AI-powered infrastructure code fixer using Google Gemini.

    Generates secure code fixes with CIS Benchmark compliance awareness.
    """

    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-1.5-pro"):
        """
        Initialize the Gemini fixer.

        Args:
            api_key: Google Gemini API key (defaults to GEMINI_API_KEY env var)
            model_name: Gemini model to use
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model_name
        self.model = None

        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(model_name)
        else:
            print("[GeminiFixer] Warning: No API key provided. Fix generation will be disabled.")

    def is_available(self) -> bool:
        """Check if Gemini is configured and available."""
        return self.model is not None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def generate_fix(
        self,
        file_content: str,
        vulnerability: Vulnerability
    ) -> Optional[Tuple[str, str]]:
        """
        Generate a secure fix for the given vulnerability.

        Args:
            file_content: The original file content
            vulnerability: The Vulnerability object with issue details

        Returns:
            Tuple of (fixed_code, explanation) or None if generation fails
        """
        if not self.is_available():
            print("[GeminiFixer] Cannot generate fix: API not configured")
            return None

        prompt = self._build_prompt(file_content, vulnerability)

        try:
            response = self.model.generate_content(prompt)
            return self._parse_response(response.text)
        except Exception as e:
            print(f"[GeminiFixer] Error generating fix: {e}")
            return None

    def _build_prompt(self, file_content: str, vuln: Vulnerability) -> str:
        """
        Build an enhanced prompt with CIS Benchmark context.

        Args:
            file_content: The original infrastructure code
            vuln: Vulnerability details

        Returns:
            Formatted prompt string
        """
        cis_context = ""
        if vuln.has_compliance_mapping:
            cis_context = f"""
    CIS BENCHMARK REFERENCE: {vuln.cis_benchmark}
    CIS REQUIREMENT: {vuln.cis_title}
    SOC 2 CONTROLS: {vuln.soc2_controls}
    PCI-DSS CONTROLS: {vuln.pci_dss_controls}
    """

        return f"""You are a DevSecOps Expert specializing in infrastructure security and compliance.

TASK: Fix a security vulnerability in Terraform/IaC code while maintaining CIS Benchmark compliance.

VULNERABILITY DETAILS:
- Scanner: {vuln.scanner.upper()}
- Check ID: {vuln.check_id}
- Description: {vuln.check_name}
- Severity: {vuln.severity.value}
- Resource: {vuln.resource}
- File: {vuln.file_path}
- Lines: {vuln.line_start}-{vuln.line_end}
{cis_context}
ORIGINAL FILE CONTENT:
```hcl
{file_content}
```

INSTRUCTIONS:
1. Fix ONLY the specific security vulnerability identified above
2. Maintain all existing functionality and other resources
3. Follow Terraform best practices and proper formatting
4. Do NOT change resource names unless absolutely necessary
5. Preserve existing variable references and dependencies

RESPONSE FORMAT:
Provide your response in TWO clearly separated sections:

### FIXED_CODE ###
```hcl
[Your fixed Terraform code here - the complete file with the fix applied]
```

### EXPLANATION ###
[Brief explanation of:
1. What security risk existed
2. What you changed to fix it
3. How this aligns with {vuln.cis_benchmark if vuln.has_compliance_mapping else "security best practices"}
]

Remember: Return the COMPLETE fixed file, not just the changed section.
"""

    def _parse_response(self, response_text: str) -> Optional[Tuple[str, str]]:
        """
        Parse the AI response to extract code and explanation.

        Args:
            response_text: Raw response from Gemini

        Returns:
            Tuple of (fixed_code, explanation) or None
        """
        try:
            fixed_code = ""
            explanation = ""

            # Extract code block
            if "### FIXED_CODE ###" in response_text:
                code_section = response_text.split("### FIXED_CODE ###")[1]
                if "### EXPLANATION ###" in code_section:
                    code_section = code_section.split("### EXPLANATION ###")[0]

                # Extract code from markdown code block
                if "```hcl" in code_section:
                    fixed_code = code_section.split("```hcl")[1].split("```")[0].strip()
                elif "```terraform" in code_section:
                    fixed_code = code_section.split("```terraform")[1].split("```")[0].strip()
                elif "```" in code_section:
                    fixed_code = code_section.split("```")[1].split("```")[0].strip()
                else:
                    fixed_code = code_section.strip()

            # Fallback: try to extract any code block
            if not fixed_code:
                if "```hcl" in response_text:
                    fixed_code = response_text.split("```hcl")[1].split("```")[0].strip()
                elif "```terraform" in response_text:
                    fixed_code = response_text.split("```terraform")[1].split("```")[0].strip()

            # Extract explanation
            if "### EXPLANATION ###" in response_text:
                explanation = response_text.split("### EXPLANATION ###")[1].strip()
                # Clean up any trailing code blocks
                if "```" in explanation:
                    explanation = explanation.split("```")[0].strip()
            else:
                # Generate basic explanation
                explanation = "Security vulnerability addressed according to best practices."

            if fixed_code:
                return (fixed_code, explanation)
            else:
                print("[GeminiFixer] Could not extract code from response")
                return None

        except Exception as e:
            print(f"[GeminiFixer] Error parsing response: {e}")
            return None

    def generate_pr_description(self, vulnerability: Vulnerability, explanation: str) -> str:
        """
        Generate an enhanced PR description with compliance context.

        Args:
            vulnerability: The fixed vulnerability
            explanation: The AI-generated explanation

        Returns:
            Formatted PR description markdown
        """
        compliance_section = ""
        if vulnerability.has_compliance_mapping:
            compliance_section = f"""
### Compliance Impact

| Framework | Control | Status |
|-----------|---------|--------|
| **CIS AWS Foundations** | {vulnerability.cis_benchmark} | Remediated |
| **SOC 2** | {vulnerability.soc2_controls} | Remediated |
| **PCI-DSS** | {vulnerability.pci_dss_controls} | Remediated |

**CIS Requirement:** {vulnerability.cis_title}
"""

        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵",
        }.get(vulnerability.severity.value, "⚪")

        return f"""## Security Vulnerability Fix {severity_emoji}

**Vulnerability ID:** `{vulnerability.check_id}`
**Severity:** {severity_emoji} **{vulnerability.severity.value}**
**Scanner:** {vulnerability.scanner.upper()}
**File:** `{vulnerability.file_path}`

---

### Description

{vulnerability.check_name}

### Risk Assessment

This vulnerability was identified as **{vulnerability.severity.value}** severity because it could potentially:
- Expose infrastructure to unauthorized access
- Violate compliance requirements
- Create security gaps in the cloud environment

### Remediation Applied

{explanation}
{compliance_section}
---

### Verification Steps

1. Review the code changes in the Files tab
2. Ensure the fix aligns with your organization's security policies
3. Run `terraform plan` to verify no unintended changes
4. Consider running additional security scans

---

> This PR was automatically generated by **DevSecOps Security Sentinel**
> AI-powered infrastructure security remediation
"""
