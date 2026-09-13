"""HTTP transport abstraction.

The SDK stays dependency-light: the default transport is stdlib ``urllib``. The
:class:`Transport` protocol lets callers inject ``requests``/``httpx`` or, in tests,
a fake that never touches the network.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, Mapping, Protocol

from .exceptions import TransportError


@dataclass
class Response:
    status: int
    headers: Dict[str, str]
    body: bytes


class Transport(Protocol):
    def send(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
    ) -> Response:
        """Perform one HTTP round trip.

        MUST raise :class:`TransportError` for any network failure, timeout, DNS
        error, or connection reset -- i.e. the cases where no HTTP status exists.
        A normal HTTP error status (4xx/5xx) MUST be returned as a :class:`Response`,
        not raised, so the client can parse the RFC 7807 body.
        """
        ...


class UrllibTransport:
    """Default transport built on :mod:`urllib.request` (no third-party deps)."""

    def send(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
    ) -> Response:
        req = urllib.request.Request(
            url,
            data=body if body else None,
            headers=dict(headers),
            method=method.upper(),
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return Response(
                    status=resp.status,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=resp.read(),
                )
        except urllib.error.HTTPError as exc:
            # An HTTP error status is a real response (carries the problem+json body).
            return Response(
                status=exc.code,
                headers={k.lower(): v for k, v in (exc.headers or {}).items()},
                body=exc.read() if hasattr(exc, "read") else b"",
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # No HTTP response at all -> this is what the fail-mode policy reacts to.
            raise TransportError(f"request to {url} failed: {exc}") from exc
