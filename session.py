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

Auth flow:
  POST /rest/token  →  {token: <int>}  +  Set-Cookie: TNS_SESSIONID=...
  Every request     →  X-SecurityCenter-Token: <token>  +  Cookie (auto via jar)
  DELETE /rest/token → logout
"""

import asyncio
import logging
import os
import ssl
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class TenableSessionError(Exception):
    pass


class TenableSession:
    def __init__(self):
        self.host: str = os.environ["SC_HOST"].rstrip("/")
        self.username: str = os.environ["SC_USERNAME"]
        self.password: str = os.environ["SC_PASSWORD"]
        self.port: int = int(os.environ.get("SC_PORT", "443"))
        self.verify_ssl: bool = os.environ.get("SC_VERIFY_SSL", "true").lower() == "true"

        self._token: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._lock = asyncio.Lock()
        self._initialized = False

    def _build_client(self) -> httpx.AsyncClient:
        ssl_context = ssl.create_default_context()
        if not self.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        return httpx.AsyncClient(
            base_url=f"https://{self.host}:{self.port}/rest",
            verify=ssl_context if self.verify_ssl else False,
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={"Content-Type": "application/json"},
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
                body = data.get("response", {})

            self._token = str(body["token"])
            self._initialized = True
            logger.info("Session established (token=%s)", self._token)

        except httpx.HTTPStatusError as e:
            raise TenableSessionError(f"HTTP error during login: {e}") from e
        except KeyError as e:
            raise TenableSessionError(f"Unexpected login response shape: {e}") from e

    async def _ensure(self):
        """Guarantee a live session exists. Safe to call concurrently."""
        if self._initialized:
            return
        async with self._lock:
            if not self._initialized:  # re-check after acquiring lock
                await self._login()

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict = None,
        json: dict = None,
        _retry: bool = True,
    ) -> dict:
        """Make an authenticated request, re-authing once on 401/403."""
        await self._ensure()

        try:
            resp = await self._client.request(
                method,
                path,
                params=params,
                json=json,
                headers={"X-SecurityCenter-Token": self._token},
            )

            if resp.status_code in (401, 403) and _retry:
                logger.warning("Token rejected (%s) — re-authenticating", resp.status_code)
                async with self._lock:
                    self._initialized = False
                await self._login()
                return await self.request(method, path, params=params, json=json, _retry=False)

            resp.raise_for_status()
            return resp.json()

        except httpx.HTTPStatusError as e:
            raise TenableSessionError(
                f"Tenable.sc {method} {path} → {e.response.status_code}: "
                f"{e.response.text[:400]}"
            ) from e

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
        try:
            await self._client.delete(
                "/token",
                headers={"X-SecurityCenter-Token": self._token},
            )
            logger.info("Session logged out cleanly")
        except Exception as e:
            logger.warning("Logout error (ignored): %s", e)
        finally:
            self._initialized = False
            self._token = None
            await self._client.aclose()
            self._client = None


# Singleton — shared across all tool modules
session = TenableSession()
