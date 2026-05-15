# tenable.sc-mcp

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that wraps the [Tenable.sc](https://docs.tenable.com/security-center/api/) REST API and exposes it over an SSE endpoint. Deploy it as a Docker container and connect it to Claude, Cursor, or any MCP-compatible system to query vulnerabilities, manage scans, and analyze your security posture in natural language.

```
"Show me all critical vulnerabilities with known exploits discovered in the last 30 days"
"Which hosts have the most unpatched highs?"
"Launch scan 42 and tell me when it finishes"
```

---

## How it works

```
Claude / Cursor / any MCP client
         │
         │  HTTP SSE  (port 8080)
         ▼
┌─────────────────────────────┐
│     tenable.sc-mcp          │
│                             │
│  FastMCP SSE layer          │
│  ┌──────────────────────┐   │
│  │  TenableSession      │   │  ← single cached session per container
│  │  (lazy init,         │   │    re-auths on 401, clean logout on stop
│  │   token + cookie)    │   │
│  └──────────────────────┘   │
└─────────────────────────────┘
         │
         │  HTTPS
         ▼
  Tenable.sc REST API
```

**Session strategy:** The server authenticates once on the first tool call and caches the token and session cookie for the lifetime of the container. It re-authenticates automatically if the token expires (401/403) and logs out cleanly when the container stops. This avoids hammering Tenable.sc's per-user concurrent session limit, which per-request auth would quickly exhaust.

---

## Prerequisites

- Docker + Docker Compose
- A Tenable.sc instance (on-prem) with a service account
- An MCP-compatible client (Claude Desktop, Cursor, etc.)

---

## Quick start

### 1. Clone and configure

```bash
git clone https://github.com/sparksbenjamin/tennable.sc-mcp.git
cd tennable.sc-mcp
cp .env.example .env
```

Edit `.env`:

```env
SC_HOST=securitycenter.example.com
SC_USERNAME=your_service_account
SC_PASSWORD=your_password
```

### 2. Build and run

```bash
docker compose up -d
```

The SSE endpoint is now live at `http://localhost:8080/sse`.

### 3. Connect from Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your OS:

```json
{
  "mcpServers": {
    "tenable-sc": {
      "url": "http://localhost:8080/sse"
    }
  }
}
```

Restart Claude Desktop. You should see the Tenable.sc tools available in the tool picker.

### 4. Connect from Cursor

In Cursor Settings → MCP, add a new server with the URL `http://localhost:8080/sse`.

---

## Using a pre-built image

If you don't want to build from source, pull the published image directly:

```bash
docker pull ghcr.io/sparksbenjamin/tennable.sc-mcp:latest
```

Then run with just a `.env` file — no source code needed:

```bash
docker run -d \
  --name tenable-sc-mcp \
  --restart unless-stopped \
  -p 8080:8080 \
  --env-file .env \
  ghcr.io/sparksbenjamin/tennable.sc-mcp:latest
```

Or with `docker-compose.prod.yml`:

```bash
docker compose -f docker-compose.prod.yml up -d
```

---

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SC_HOST` | ✅ | — | Tenable.sc hostname or IP |
| `SC_USERNAME` | ✅ | — | Service account username |
| `SC_PASSWORD` | ✅ | — | Service account password |
| `SC_PORT` | | `443` | Tenable.sc HTTPS port |
| `SC_VERIFY_SSL` | | `true` | Set `false` for self-signed certs |
| `MCP_PORT` | | `8080` | Port the SSE server listens on |
| `MCP_HOST` | | `0.0.0.0` | Bind address |
| `LOG_LEVEL` | | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

> **Use a dedicated read-only service account.** The MCP server only needs read access for most operations. Restrict the account's Tenable.sc role accordingly.

---

## Available tools

### Scans

| Tool | Description |
|---|---|
| `list_scans` | List all configured scans |
| `get_scan` | Get details of a specific scan |
| `launch_scan` | Start a scan by ID |
| `pause_scan` | Pause a running scan |
| `resume_scan` | Resume a paused scan |
| `stop_scan` | Stop a running scan |
| `list_scan_results` | List completed/running scan results, with optional status filter |
| `get_scan_result` | Get details of a specific scan result |
| `delete_scan_result` | Delete a scan result |

### Vulnerabilities

These tools use Tenable.sc's `/analysis` endpoint, which supports multiple aggregation modes controlled by the `tool` parameter.

| Tool | Description |
|---|---|
| `query_vulnerabilities` | Flexible query: per-host details, severity sums, top IPs, port grouping, remediation summary, and more |
| `get_vulnerability_summary_by_severity` | Counts grouped by Info / Low / Medium / High / Critical |
| `get_top_vulnerable_hosts` | Hosts ranked by vulnerability count, filterable by severity |
| `get_exploitable_vulnerabilities` | Vulnerabilities with known exploits, sorted by severity |

### Assets, Repositories & System

| Tool | Description |
|---|---|
| `list_assets` | List all asset lists (static, dynamic, combination) |
| `get_asset` | Get asset details, optionally including IP members |
| `create_static_asset` | Create a static asset list from IPs or CIDR ranges |
| `list_repositories` | List vulnerability repositories |
| `get_repository` | Get repository details |
| `get_system_status` | SC version, license info, feed status |
| `get_current_user` | Currently authenticated user |
| `list_scanners` | Registered scanners and their status |
| `list_scan_policies` | Available scan policies |
| `list_alerts` | Configured alerts |
| `list_report_definitions` | Available report definitions |
| `launch_report` | Generate a report from a definition |

---

## Self-signed certificates

Most on-prem Tenable.sc deployments use self-signed certs. Set `SC_VERIFY_SSL=false` in your `.env` to disable certificate verification.

---

## Extending the server

Add a new file to `src/tools/` following this pattern, then register it in `src/tools/__init__.py`:

```python
from mcp.server.fastmcp import FastMCP
from session import session, TenableSessionError
import json

def register(mcp: FastMCP):

    @mcp.tool()
    async def my_tool(param: str) -> str:
        """Description the LLM uses to decide when to call this."""
        try:
            data = await session.get(f"/resource/{param}")
            return json.dumps(data.get("response", {}), indent=2)
        except TenableSessionError as e:
            return f"Error: {e}"
```

---

## CI/CD

The GitHub Actions workflow in `.github/workflows/docker-publish.yml` automatically builds and pushes a multi-arch image (`linux/amd64` + `linux/arm64`) to GitHub Container Registry on every push to `main` and on version tags.

| Event | Tags produced |
|---|---|
| Push to `main` | `:latest`, `:main` |
| Tag `v1.2.3` | `:1.2.3`, `:1.2`, `:1`, `:latest` |
| Pull request | Build only, no push |

No secrets need to be configured — the workflow uses the automatically provided `GITHUB_TOKEN`.

---

## Security considerations

- Store `.env` with `chmod 600` and never commit it to source control
- Use a **scoped service account** on Tenable.sc — read-only where possible
- If exposing the SSE endpoint beyond localhost, put it behind a reverse proxy with TLS and authentication
- The container runs as a non-root user with a read-only filesystem

---

## License

MIT — see [LICENSE](LICENSE).
