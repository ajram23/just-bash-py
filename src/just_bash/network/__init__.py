"""Network module for just-bash."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

from ..types import AllowedUrl, NetworkConfig, RequestTransform


class NetworkAccessDeniedError(Exception):
    """Raised when a URL is outside the configured network policy."""

    def __init__(self, url: str, reason: str = "URL not in allow-list") -> None:
        super().__init__(f"Network access denied: {reason}: {url}")


class MethodNotAllowedError(Exception):
    """Raised when an HTTP method is outside the configured network policy."""

    def __init__(self, method: str, allowed_methods: list[str]) -> None:
        super().__init__(
            f"HTTP method '{method}' not allowed. Allowed methods: {', '.join(allowed_methods)}"
        )


class RedirectNotAllowedError(Exception):
    """Raised when a redirect target is outside the configured network policy."""

    def __init__(self, url: str) -> None:
        super().__init__(f"Redirect target not in allow-list: {url}")


class TooManyRedirectsError(Exception):
    """Raised when a request exceeds the configured redirect limit."""

    def __init__(self, max_redirects: int) -> None:
        super().__init__(f"Too many redirects (max: {max_redirects})")


class ResponseTooLargeError(Exception):
    """Raised when a response exceeds the configured size limit."""

    def __init__(self, max_size: int) -> None:
        super().__init__(f"Response body too large (max: {max_size} bytes)")


def _entry_url(entry: str | AllowedUrl | dict[str, Any]) -> str:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return str(entry.get("url", ""))
    return entry.url


def _path_matches(path: str, prefix: str) -> bool:
    if prefix in ("", "/"):
        return True
    if "%2f" in path.lower() or "%5c" in path.lower() or "\\" in path:
        return False
    if prefix.endswith("/"):
        return path.startswith(prefix)
    return path == prefix or path.startswith(f"{prefix}/")


def _matches_allow_entry(url: str, allowed_entry: str) -> bool:
    parsed_url = urlparse(url)
    parsed_allowed = urlparse(allowed_entry)
    if not parsed_url.scheme or not parsed_url.netloc:
        return False
    if not parsed_allowed.scheme or not parsed_allowed.netloc:
        return False

    url_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
    allowed_origin = f"{parsed_allowed.scheme}://{parsed_allowed.netloc}"
    if url_origin != allowed_origin:
        return False
    return _path_matches(parsed_url.path or "/", parsed_allowed.path or "/")


def _is_private_hostname(hostname: str) -> bool:
    host = hostname.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


async def _resolve_host(hostname: str, port: int) -> list[dict[str, Any]]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for family, _, proto, _, sockaddr in infos:
        address = sockaddr[0]
        key = (address, family)
        if key in seen:
            continue
        seen.add(key)
        results.append(
            {
                "hostname": hostname,
                "host": address,
                "port": port,
                "family": family,
                "proto": proto,
                "flags": socket.AI_NUMERICHOST,
            }
        )
    return results


class _PinnedResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, hostname: str, records: list[dict[str, Any]]) -> None:
        self._hostname = hostname
        self._records = records

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[dict[str, Any]]:
        if host == self._hostname:
            return [{**record, "port": port} for record in self._records]
        return await _resolve_host(host, port)

    async def close(self) -> None:
        return None


def _merge_headers(
    user_headers: dict[str, str] | None,
    firewall_headers: dict[str, str],
) -> dict[str, str]:
    merged = dict(user_headers or {})
    for key, value in firewall_headers.items():
        existing = next((k for k in merged if k.lower() == key.lower()), None)
        if existing is not None:
            del merged[existing]
        merged[key] = value
    return merged


def make_default_fetch(config: NetworkConfig):
    """Create an aiohttp-backed secure fetch function for curl."""

    entries = config.allowed_url_prefixes
    allowed_methods = (
        ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        if config.dangerously_allow_full_internet_access
        else [method.upper() for method in config.allowed_methods]
    )

    async def check_allowed(url: str) -> list[dict[str, Any]] | None:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise NetworkAccessDeniedError(url, "invalid URL")

        if not config.dangerously_allow_full_internet_access and not any(
            _matches_allow_entry(url, _entry_url(entry)) for entry in entries
        ):
            raise NetworkAccessDeniedError(url)

        if not config.deny_private_ranges:
            return None

        hostname = parsed.hostname or ""
        if _is_private_hostname(hostname):
            raise NetworkAccessDeniedError(url, "private/loopback IP address blocked")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        records = await _resolve_host(hostname, port)
        for record in records:
            if _is_private_hostname(record["host"]):
                raise NetworkAccessDeniedError(
                    url, "hostname resolves to private/loopback IP address"
                )
        return records

    def check_method_allowed(method: str) -> None:
        if config.dangerously_allow_full_internet_access:
            return
        if method.upper() not in allowed_methods:
            raise MethodNotAllowedError(method.upper(), allowed_methods)

    def firewall_headers(url: str) -> dict[str, str]:
        merged: dict[str, str] = {}
        for entry in entries:
            entry_url = _entry_url(entry)
            if isinstance(entry, str) or not _matches_allow_entry(url, entry_url):
                continue
            transforms: list[RequestTransform | dict[str, Any]]
            if isinstance(entry, dict):
                transforms = entry.get("transform", [])
            else:
                transforms = entry.transform
            for transform in transforms:
                headers = (
                    transform.get("headers", {})
                    if isinstance(transform, dict)
                    else transform.headers
                )
                merged.update(headers)
        return merged

    async def read_limited_body(resp: aiohttp.ClientResponse) -> bytes:
        max_size = config.max_response_size
        chunks: list[bytes] = []
        total = 0

        if max_size > 0:
            content_length = resp.headers.get("content-length")
            if content_length and int(content_length) > max_size:
                raise ResponseTooLargeError(max_size)

        async for chunk in resp.content.iter_chunked(64 * 1024):
            total += len(chunk)
            if max_size > 0 and total > max_size:
                raise ResponseTooLargeError(max_size)
            chunks.append(chunk)
        return b"".join(chunks)

    async def fetch(url: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        options = options or {}
        method = (options.get("method") or "GET").upper()
        check_method_allowed(method)

        current_url = url
        redirect_count = 0
        follow_redirects = options.get("followRedirects", True)
        max_redirects = int(options.get("maxRedirects", config.max_redirects))
        timeout_ms = min(
            int(options.get("timeoutMs") or config.timeout_ms),
            config.timeout_ms,
        )
        body = options.get("body")
        if body is not None and method in {"GET", "HEAD", "OPTIONS"}:
            body = None

        while True:
            pinned_records = await check_allowed(current_url)
            timeout = aiohttp.ClientTimeout(total=timeout_ms / 1000)
            connector = (
                aiohttp.TCPConnector(
                    resolver=_PinnedResolver(urlparse(current_url).hostname or "", pinned_records)
                )
                if pinned_records
                else None
            )
            try:
                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    headers = _merge_headers(
                        options.get("headers") or {},
                        firewall_headers(current_url),
                    )
                    async with session.request(
                        method,
                        current_url,
                        headers=headers,
                        data=body,
                        allow_redirects=False,
                        auto_decompress=False,
                    ) as resp:
                        if resp.status in {301, 302, 303, 307, 308} and follow_redirects:
                            location = resp.headers.get("location")
                            if not location:
                                response_body = await read_limited_body(resp)
                                return {
                                    "status": resp.status,
                                    "statusText": resp.reason or "",
                                    "headers": {k.lower(): v for k, v in resp.headers.items()},
                                    "body": response_body,
                                    "url": current_url,
                                    "redirectCount": redirect_count,
                                }

                            redirect_url = urljoin(current_url, location)
                            try:
                                await check_allowed(redirect_url)
                            except NetworkAccessDeniedError as exc:
                                raise RedirectNotAllowedError(redirect_url) from exc

                            redirect_count += 1
                            if redirect_count > max_redirects:
                                raise TooManyRedirectsError(max_redirects)

                            current_url = redirect_url
                            continue

                        response_body = await read_limited_body(resp)
                        return {
                            "status": resp.status,
                            "statusText": resp.reason or "",
                            "headers": {k.lower(): v for k, v in resp.headers.items()},
                            "body": response_body,
                            "url": str(resp.url),
                            "redirectCount": redirect_count,
                        }
            except TimeoutError as exc:
                raise TimeoutError("operation timeout") from exc

    return fetch
