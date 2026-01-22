"""Abstract base class for AI providers."""
from abc import ABC, abstractmethod
from typing import Optional, Tuple
from models.vulnerability import Vulnerability


class BaseAIProvider(ABC):
    """Abstract base class for AI-powered code fixers."""

    def __init__(self, model_name: str = ""):
        """
        Initialize the AI provider.

        Args:
            model_name: The model to use for generation
        """
        self.model_name = model_name
        self.name: str = "base"

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the AI provider is configured and available.

        Returns:
            True if provider is available, False otherwise
        """
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def review_fix(
        self,
        original_code: str,
        fixed_code: str,
        vulnerability: Vulnerability
    ) -> Tuple[bool, str]:
        """
        Review a generated fix for correctness and safety.

        Args:
            original_code: The original vulnerable code
            fixed_code: The AI-generated fix
            vulnerability: The vulnerability being fixed

        Returns:
            Tuple of (is_valid, review_comments)
        """
        pass

    def get_name(self) -> str:
        """Return the provider name."""
        return self.name

    def build_fix_prompt(self, file_content: str, vuln: Vulnerability) -> str:
        """
        Build a standardized prompt for fix generation.

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

    def build_review_prompt(
        self,
        original_code: str,
        fixed_code: str,
        vuln: Vulnerability
    ) -> str:
        """
        Build a prompt for reviewing a generated fix.

        Args:
            original_code: The original vulnerable code
            fixed_code: The AI-generated fix
            vuln: The vulnerability being fixed

        Returns:
            Formatted review prompt
        """
        return f"""You are a Senior Security Engineer reviewing an AI-generated code fix.

TASK: Review this security fix for correctness, safety, and potential issues.

VULNERABILITY BEING FIXED:
- Check ID: {vuln.check_id}
- Description: {vuln.check_name}
- Severity: {vuln.severity.value}
- CIS Benchmark: {vuln.cis_benchmark}

ORIGINAL CODE:
```hcl
{original_code}
```

PROPOSED FIX:
```hcl
{fixed_code}
```

REVIEW CRITERIA:
1. Does the fix actually address the vulnerability?
2. Does the fix introduce any new security issues?
3. Does the fix break existing functionality?
4. Is the fix syntactically correct?
5. Does the fix follow infrastructure best practices?

RESPONSE FORMAT:
### VERDICT ###
[APPROVED or REJECTED]

### ISSUES ###
[List any issues found, or "None" if the fix is correct]

### RECOMMENDATION ###
[Brief recommendation for improvement if REJECTED, or confirmation if APPROVED]
"""

    def parse_fix_response(self, response_text: str) -> Optional[Tuple[str, str]]:
        """
        Parse the AI response to extract code and explanation.

        Args:
            response_text: Raw response from AI

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
                if "```" in explanation:
                    explanation = explanation.split("```")[0].strip()
            else:
                explanation = "Security vulnerability addressed according to best practices."

            if fixed_code:
                return (fixed_code, explanation)
            return None

        except Exception as e:
            print(f"[{self.name}] Error parsing response: {e}")
            return None

    def parse_review_response(self, response_text: str) -> Tuple[bool, str]:
        """
        Parse the review response to extract verdict and comments.

        Args:
            response_text: Raw review response

        Returns:
            Tuple of (is_approved, comments)
        """
        try:
            is_approved = "APPROVED" in response_text.upper() and "REJECTED" not in response_text.upper()

            comments = ""
            if "### ISSUES ###" in response_text:
                issues_section = response_text.split("### ISSUES ###")[1]
                if "### RECOMMENDATION ###" in issues_section:
                    comments = issues_section.split("### RECOMMENDATION ###")[0].strip()
                else:
                    comments = issues_section.strip()

            if "### RECOMMENDATION ###" in response_text:
                rec = response_text.split("### RECOMMENDATION ###")[1].strip()
                comments = f"{comments}\n\nRecommendation: {rec}" if comments else rec

            return (is_approved, comments if comments else "No issues found.")

        except Exception:
            return (False, "Error parsing review response")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model='{self.model_name}')"
