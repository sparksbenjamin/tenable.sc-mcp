"""
Tenable.sc Session Manager
---------------------------
Maintains a single cached session (token + cookie jar) for the lifetime of
the container process:

  - Lazy init: authenticates on the first tool call, not at startup
  - Auto re-auth: transparently re-logs in on 401/403 (token expiry)
  - Session limit handling: retries with releaseSession=true if SC says the
    user has hit their max concurrent session cap
  - Graceful shutdown: DELETE /rest/token on SIGTERM/SIGINT via main.py
  - Rich error surfacing: parses the SC JSON error envelope so tool callers
    get "error_code / error_msg" instead of raw HTTP noise

Auth flow:
  POST /rest/token  →  {token: <int>}  +  Set-Cookie: TNS_SESSIONID=...
  Every request     →  X-SecurityCenter-Token: <token>  +  Cookie (auto via jar)
  DELETE /rest/token → logout
"""

import asyncio
import logging
import os
import ssl
from typing import Any, Optional, Union

import httpx

logger = logging.getLogger(__name__)


class TenableSessionError(Exception):
    pass


JsonDict = dict[str, Any]


def _sc_error_detail(payload: Any) -> Optional[str]:
    """Extract a human-readable message from an SC error envelope, if any."""
    if isinstance(payload, dict):
        code = payload.get("error_code", 0)
        msg = payload.get("error_msg", "")
        if code or msg:
            return f"error_code={code}: {msg}".strip(": ")
    return None


class TenableSession:
    def __init__(self):
        self.host: str = os.environ["SC_HOST"].rstrip("/")
        self.username: str = os.environ["SC_USERNAME"]
        self.password: str = os.environ["SC_PASSWORD"]
        self.port: int = int(os.environ.get("SC_PORT", "443"))
        self.verify_ssl: bool = os.environ.get("SC_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
        self.timeout: float = float(os.environ.get("SC_TIMEOUT", "30"))

        self._token: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._lock = asyncio.Lock()
        self._initialized = False

    def _build_client(self) -> httpx.AsyncClient:
        ssl_context = None
        if self.verify_ssl:
            ssl_context = ssl.create_default_context()

        # NOTE: no client-level Content-Type — it would override the
        # multipart boundary header on file uploads (httpx only sets
        # Content-Type per-request when building bodies).
        return httpx.AsyncClient(
            base_url=f"https://{self.host}:{self.port}/rest",
            verify=ssl_context if ssl_context is not None else False,
            timeout=httpx.Timeout(self.timeout, connect=min(10.0, self.timeout)),
        )

    async def _login(self):
        """Authenticate and cache token. Must be called with self._lock held."""
        logger.info("Authenticating with Tenable.sc at %s", self.host)

        if self._client:
            await self._client.aclose()
        self._client = self._build_client()

        try:
            resp = await self._client.post(
                "/token",
                json={
                    "username": self.username,
                    "password": self.password,
                    "releaseSession": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get("error_code", 0) != 0:
                raise TenableSessionError(f"Login failed: {data.get('error_msg', 'unknown')}")

            body = data.get("response", {})

            # SC returns releaseSession=true when the user has hit their max session cap
            if body.get("releaseSession") is True:
                logger.warning("Max sessions reached — retrying with releaseSession=true")
                resp = await self._client.post(
                    "/token",
                    json={
                        "username": self.username,
                        "password": self.password,
                        "releaseSession": True,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                if data.get("error_code", 0) != 0:
                    raise TenableSessionError(f"Login failed: {data.get('error_msg', 'unknown')}")
                body = data.get("response", {})

            self._token = str(body["token"])
            self._initialized = True
            logger.info("Session established (token=%s)", self._token)

        except httpx.HTTPStatusError as e:
            raise TenableSessionError(f"HTTP error during login: {e}") from e
        except KeyError as e:
            raise TenableSessionError(f"Unexpected login response shape: {e}") from e
        except httpx.RequestError as e:
            raise TenableSessionError(
                f"Could not reach Tenable.sc at {self.host}:{self.port}: {e}"
            ) from e

    async def _ensure(self):
        """Guarantee a live session exists. Safe to call concurrently."""
        if self._initialized:
            return
        async with self._lock:
            if not self._initialized:  # re-check after acquiring lock
                await self._login()

    async def request_raw(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict] = None,
        json: Optional[dict] = None,
        content: Optional[bytes] = None,
        files: Optional[dict] = None,
        headers: Optional[dict] = None,
        _retry: bool = True,
    ) -> httpx.Response:
        """Make an authenticated request, re-authing once on 401/403.

        Returns the raw httpx.Response (use for binary downloads / uploads).
        """
        await self._ensure()
        client = self._client
        assert client is not None  # _ensure() guarantees a live client

        try:
            merged_headers: dict[str, str] = {"X-SecurityCenter-Token": self._token or ""}
            if headers:
                merged_headers.update(headers)

            resp = await client.request(
                method,
                path,
                params=params,
                json=json,
                content=content,
                files=files,
                headers=merged_headers,
            )

            if resp.status_code in (401, 403) and _retry:
                logger.warning("Token rejected (%s) — re-authenticating", resp.status_code)
                async with self._lock:
                    if self._initialized:
                        self._initialized = False
                    await self._login()
                return await self.request_raw(
                    method, path, params=params, json=json, content=content,
                    files=files, headers=headers, _retry=False,
                )

            if resp.is_error:
                detail = None
                try:
                    detail = _sc_error_detail(resp.json())
                except ValueError:
                    pass
                raise TenableSessionError(
                    f"Tenable.sc {method} {path} failed with HTTP {resp.status_code}"
                    + (f": {detail}" if detail else f": {resp.text[:300]}")
                )

            return resp

        except httpx.RequestError as e:
            raise TenableSessionError(
                f"Connection error talking to Tenable.sc ({method} {path}): {e}"
            ) from e

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict] = None,
        json: Optional[dict] = None,
        _retry: bool = True,
    ) -> dict:
        """Make an authenticated request and return the parsed JSON envelope.

        Raises TenableSessionError when SC reports a non-zero error_code.
        """
        resp = await self.request_raw(method, path, params=params, json=json)
        try:
            data = resp.json()
        except ValueError as e:
            raise TenableSessionError(
                f"Tenable.sc {method} {path} returned a non-JSON response "
                f"(first 200 chars): {resp.text[:200]!r}"
            ) from e

        if isinstance(data, dict):
            code = data.get("error_code", 0)
            msg = data.get("error_msg", "")
            if code:
                raise TenableSessionError(
                    f"Tenable.sc {method} {path} → error_code={code}: {msg}"
                )

        return data

    async def get(self, path: str, **kw) -> dict:
        return await self.request("GET", path, **kw)

    async def post(self, path: str, **kw) -> dict:
        return await self.request("POST", path, **kw)

    async def patch(self, path: str, **kw) -> dict:
        return await self.request("PATCH", path, **kw)

    async def delete(self, path: str, **kw) -> dict:
        return await self.request("DELETE", path, **kw)

    async def logout(self):
        """Clean logout — called by main.py on shutdown."""
        if not self._initialized or not self._client:
            return
        client = self._client
        try:
            await client.delete(
                "/token",
                headers={"X-SecurityCenter-Token": self._token or ""},
            )
            logger.info("Session logged out cleanly")
        except Exception as e:
            logger.warning("Logout error (ignored): %s", e)
        finally:
            self._initialized = False
            self._token = None
            self._client = None
            await client.aclose()


# Singleton — shared across all tool modules
session = TenableSession()
