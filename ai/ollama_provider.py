"""Ollama local AI provider for code fixing."""
import os
from typing import Optional, Tuple
from tenacity import retry, stop_after_attempt, wait_exponential

from ai.base import BaseAIProvider
from models.vulnerability import Vulnerability


class OllamaProvider(BaseAIProvider):
    """
    AI-powered infrastructure code fixer using local Ollama models.

    Generates secure code fixes with CIS Benchmark compliance awareness.
    Runs entirely locally for maximum privacy.
    """

    def __init__(
        self,
        model_name: str = "codellama",
        host: Optional[str] = None
    ):
        """
        Initialize the Ollama provider.

        Args:
            model_name: Ollama model to use (default: codellama)
            host: Ollama server host (defaults to OLLAMA_HOST env var or localhost:11434)
        """
        super().__init__(model_name)
        self.name = "ollama"
        self.host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.client = None
        self._available = False

        try:
            import ollama
            self.client = ollama.Client(host=self.host)
            # Test connection
            self.client.list()
            self._available = True
        except ImportError:
            print("[Ollama] Warning: ollama package not installed. Run: pip install ollama")
        except Exception as e:
            print(f"[Ollama] Warning: Ollama not available at {self.host}: {e}")

    def is_available(self) -> bool:
        """Check if Ollama is running and accessible."""
        return self._available and self.client is not None

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
            print("[Ollama] Cannot generate fix: Ollama not available")
            return None

        prompt = self.build_fix_prompt(file_content, vulnerability)

        try:
            response = self.client.chat(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a DevSecOps expert specializing in infrastructure security and compliance. Generate secure code fixes."
                    },
                    {"role": "user", "content": prompt}
                ],
                options={
                    "temperature": 0.3,
                    "num_predict": 4000
                }
            )
            return self.parse_fix_response(response['message']['content'])
        except Exception as e:
            print(f"[Ollama] Error generating fix: {e}")
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
            return (False, "Ollama not available")

        prompt = self.build_review_prompt(original_code, fixed_code, vulnerability)

        try:
            response = self.client.chat(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior security engineer reviewing AI-generated code fixes. Be thorough and critical."
                    },
                    {"role": "user", "content": prompt}
                ],
                options={
                    "temperature": 0.2,
                    "num_predict": 2000
                }
            )
            return self.parse_review_response(response['message']['content'])
        except Exception as e:
            print(f"[Ollama] Error reviewing fix: {e}")
            return (False, f"Review failed: {e}")
