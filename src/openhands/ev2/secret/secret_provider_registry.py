"""Provider-implementation registry and lazy client cache.

``SecretProvider`` implementations are selected by a ``secret_providers.kind``
discriminator at request time. Provider client objects are constructed lazily
on first use and reused thereafter (a per-row connection cache). Given
providers are read-only, no explicit cleanup is required on shutdown.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING

from openhands.ev2.secret.secret_models import STATIC_PROVIDER_KIND

# The ``oauth`` kind discriminator for the OAuthSecretsProvider (sub-issue #145).
OAUTH_PROVIDER_KIND = "oauth"

if TYPE_CHECKING:
    from openhands.ev2.encryption.encryption_service import EncryptionService
    from openhands.ev2.secret.secret_provider import SecretProvider

# kind -> factory. Factories receive (provider_row_data, encryption_service)
# and return a ready-to-use provider client. Registered lazily as implementations
# land; the static provider is the only built-in for now.
_PROVIDER_FACTORIES: dict[str, Callable[..., SecretProvider]] = {}


def register_provider_factory(kind: str, factory: Callable[..., SecretProvider]) -> None:
    """Register the concrete provider factory for a ``kind`` discriminator."""
    _PROVIDER_FACTORIES[kind] = factory


def _static_provider_factory(data: dict[str, object], enc: EncryptionService) -> SecretProvider:
    from openhands.ev2.secret.static_secret_provider import StaticSecretProvider

    return StaticSecretProvider(enc)


# The static provider needs no config beyond the encryption service.
register_provider_factory(STATIC_PROVIDER_KIND, _static_provider_factory)


def _oauth_provider_factory(data: dict[str, object], enc: EncryptionService) -> SecretProvider:
    from openhands.ev2.secret.oauth_secret_provider import OAuthSecretsProvider

    return OAuthSecretsProvider(enc)


register_provider_factory(OAUTH_PROVIDER_KIND, _oauth_provider_factory)


class SecretProviderCache:
    """Per-row cache of constructed :class:`SecretProvider` clients.

    A provider client may hold long-lived connections (an AWS client, a
    1Password client); it is built once on first use and reused thereafter.
    """

    def __init__(self, enc: EncryptionService) -> None:
        self._enc = enc
        self._clients: dict[uuid.UUID, SecretProvider] = {}

    def get(
        self,
        provider_id: uuid.UUID,
        kind: str,
        data: dict[str, object],
    ) -> SecretProvider:
        """Return the cached client for a provider row, constructing it if needed."""
        client = self._clients.get(provider_id)
        if client is None:
            factory = _PROVIDER_FACTORIES.get(kind)
            if factory is None:
                raise ValueError(f"Unsupported secret provider kind: {kind!r}")
            client = factory(data, self._enc)
            self._clients[provider_id] = client
        return client

    async def aclose(self) -> None:
        """Best-effort close of every cached client (designed to be a no-op)."""
        for client in list(self._clients.values()):
            closer = getattr(client, "aclose", None)
            if callable(closer):
                await closer()
