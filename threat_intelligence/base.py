
from abc import ABC, abstractmethod
from typing import Any


class ThreatIntelligenceNotFoundError(Exception):
    """Raised when a provider has no existing report for an IOC."""


class ThreatIntelligenceProvider(ABC):
    """Base interface for threat intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the provider name."""
        pass

    @abstractmethod
    def lookup(self, ioc: str, ioc_type: str) -> dict[str, Any]:
        """Look up an IOC using the provider."""
        pass

    def lookup_normalized(
        self,
        ioc: str,
        ioc_type: str
    ) -> dict[str, Any]:
        """Look up an IOC that has already been normalized."""
        return self.lookup(ioc, ioc_type)
