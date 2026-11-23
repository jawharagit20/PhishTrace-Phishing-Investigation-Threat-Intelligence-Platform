
from typing import Any

from .base import (
    ThreatIntelligenceProvider,
    ThreatIntelligenceNotFoundError
)
from .normalizer import normalize_ioc


class ThreatIntelligenceManager:
    """Manage and execute multiple threat intelligence providers."""

    def __init__(self) -> None:
        self.providers: list[ThreatIntelligenceProvider] = []

    def register_provider(
        self,
        provider: ThreatIntelligenceProvider
    ) -> None:
        """Register a threat intelligence provider."""

        if not isinstance(provider, ThreatIntelligenceProvider):
            raise TypeError(
                "Provider must inherit from ThreatIntelligenceProvider."
            )

        if any(
            existing.name == provider.name
            for existing in self.providers
        ):
            raise ValueError(
                f"Provider already registered: {provider.name}"
            )

        self.providers.append(provider)

    def enrich(
        self,
        ioc: str,
        ioc_type: str
    ) -> dict[str, Any]:
        """Normalize an IOC and enrich it using registered providers."""

        normalized_ioc = normalize_ioc(ioc, ioc_type)

        results = []

        for provider in self.providers:
            try:
                result = provider.lookup_normalized(
                    normalized_ioc,
                    ioc_type
                )

                results.append({
                    "provider": provider.name,
                    "status": "success",
                    "data": result
                })

            except ThreatIntelligenceNotFoundError as error:
                results.append({
                    "provider": provider.name,
                    "status": "not_found",
                    "message": str(error)
                })

            except Exception as error:
                results.append({
                    "provider": provider.name,
                    "status": "error",
                    "error_type": getattr(
                        error,
                        "error_type",
                        "provider_error"
                    ),
                    "message": str(error)
                })

        return {
            "ioc": normalized_ioc,
            "ioc_type": ioc_type,
            "enrichment_results": results
        }
