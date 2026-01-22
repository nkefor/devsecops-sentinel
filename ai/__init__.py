"""AI module for DevSecOps Sentinel."""
from .base import BaseAIProvider
from .gemini_fixer import GeminiFixer
from .openai_provider import OpenAIProvider
from .claude_provider import ClaudeProvider
from .ollama_provider import OllamaProvider
from .reviewer import AIReviewer, ReviewResult

__all__ = [
    'BaseAIProvider',
    'GeminiFixer',
    'OpenAIProvider',
    'ClaudeProvider',
    'OllamaProvider',
    'AIReviewer',
    'ReviewResult',
]


def get_available_providers(config: dict = None) -> list:
    """
    Get list of available AI providers based on configuration.

    Args:
        config: Optional configuration dict with provider settings

    Returns:
        List of initialized AI provider instances
    """
    providers = []
    config = config or {}

    # Try each provider in order of preference
    provider_classes = [
        ('gemini', GeminiFixer),
        ('openai', OpenAIProvider),
        ('claude', ClaudeProvider),
        ('ollama', OllamaProvider),
    ]

    for name, cls in provider_classes:
        try:
            provider_config = config.get(name, {})
            provider = cls(**provider_config) if provider_config else cls()
            if provider.is_available():
                providers.append(provider)
        except Exception as e:
            print(f"[AI] Warning: Failed to initialize {name}: {e}")

    return providers


def get_first_available_provider(config: dict = None) -> BaseAIProvider:
    """
    Get the first available AI provider.

    Args:
        config: Optional configuration dict

    Returns:
        First available AI provider or None
    """
    providers = get_available_providers(config)
    return providers[0] if providers else None
