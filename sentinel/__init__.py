"""DevSecOps Security Sentinel - AI-Powered Infrastructure Security Remediation."""

__version__ = "2.0.0"
__author__ = "Hansen Nkefor"

from .cli import SentinelCLI, OutputFormat

__all__ = [
    'SentinelCLI',
    'OutputFormat',
    '__version__',
]
