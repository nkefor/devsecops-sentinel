"""OpenAI GPT-4 AI provider for code fixing."""
import os
from typing import Optional, Tuple
from tenacity import retry, stop_after_attempt, wait_exponential

from ai.base import BaseAIProvider
from models.vulnerability import Vulnerability


class OpenAIProvider(BaseAIProvider):
    """
    AI-powered infrastructure code fixer using OpenAI GPT-4.

    Generates secure code fixes with CIS Benchmark compliance awareness.
    """

    def __init__(self, api_key: Optional[str] = None, model_name: str = "gpt-4"):
        """
        Initialize the OpenAI provider.

        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            model_name: OpenAI model to use (default: gpt-4)
        """
        super().__init__(model_name)
        self.name = "openai"
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.client = None

        if self.api_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
            except ImportError:
                print("[OpenAI] Warning: openai package not installed. Run: pip install openai")
            except Exception as e:
                print(f"[OpenAI] Warning: Failed to initialize client: {e}")
        else:
            print("[OpenAI] Warning: No API key provided. Fix generation will be disabled.")

    def is_available(self) -> bool:
        """Check if OpenAI is configured and available."""
        return self.client is not None

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
            print("[OpenAI] Cannot generate fix: API not configured")
            return None

        prompt = self.build_fix_prompt(file_content, vulnerability)

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a DevSecOps expert specializing in infrastructure security and compliance. Generate secure code fixes."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=4000
            )
            return self.parse_fix_response(response.choices[0].message.content)
        except Exception as e:
            print(f"[OpenAI] Error generating fix: {e}")
            return None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
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
        if not self.is_available():
            return (False, "OpenAI API not configured")

        prompt = self.build_review_prompt(original_code, fixed_code, vulnerability)

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior security engineer reviewing AI-generated code fixes. Be thorough and critical."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=2000
            )
            return self.parse_review_response(response.choices[0].message.content)
        except Exception as e:
            print(f"[OpenAI] Error reviewing fix: {e}")
            return (False, f"Review failed: {e}")
