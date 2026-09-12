"""Random identifier minting shared across sandbox providers.

Both the Docker and Kubernetes sandbox providers need opaque, unguessable
identifiers for two distinct purposes:

* the ``SESSION_API_KEY`` injected into every sandbox container (the agent
  server inside the container refuses to bind ``0.0.0.0`` unless a session
  API key is set, so each sandbox must carry one); and
* the sandbox ``id`` itself (the Docker container name / K8s Deployment
  name), which doubles as the workspace bind-mount directory key and must be
  unguessable so one tenant cannot predict another's sandbox id.

Both are minted as 22-character lowercase alphanumeric strings — ``[a-z0-9]``
— which are URL-safe, DNS-1123 compliant (required for the K8s Deployment
name), and free of the ``_`` separator used by the Docker ``OHE_<sid>_<cid>``
name grammar and the ``-`` used by the K8s ``<sid>-data`` / ``<sid>-restore``
derived names. 22 chars of base36 entropy (~113 bits) is ample for collision
resistance across the sandbox fleet.
"""

from __future__ import annotations

import secrets
import string

# 22 lowercase alphanumeric chars ([a-z0-9]) — see module docstring.
_LENGTH = 22
_ALPHABET = string.ascii_lowercase + string.digits


def generate_random_id() -> str:
    """Return a 22-character lowercase alphanumeric random id."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(_LENGTH))
