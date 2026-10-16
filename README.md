# Tenable.sc MCP Server

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![Docker](https://img.shields.io/badge/docker-supported-blue)]()
[![MCP](https://img.shields.io/badge/MCP-compatible-purple)]()
[![Tests](https://img.shields.io/badge/tests-95%20passing-brightgreen)]()

A Model Context Protocol (MCP) server for Tenable.sc (SecurityCenter) that
enables AI assistants like Claude Desktop, Cursor, OpenCode, and VS Code to
securely interact with Tenable.sc through natural language.

This server exposes Tenable.sc functionality as 90+ MCP tools, allowing AI
clients to:

- Query and analyze vulnerabilities, assets, events, and mobile devices
- Launch, control, and import scans (network, agent, and web app)
- Manage scan policies, audit files, credentials, and asset lists
- Create and apply accept/recast risk rules
- Launch and distribute reports, import/export dashboards
- Manage repositories, organizations, users, and feeds
- Download and upload files (reports, policies, scan results)
- Reach any other REST endpoint via a generic passthrough

Supports three transports:

- `stdio` for local desktop MCP clients
- `streamable-http` for remote/shared deployments (default)
- `sse` for legacy clients

---

## Quick Start

### 1. Create `.env`

```env
SC_HOST=securitycenter.example.com
SC_USERNAME=svc_mcp
SC_PASSWORD=super-secret-password

# Optional
SC_PORT=443
SC_VERIFY_SSL=true
SC_TIMEOUT=30

MCP_TRANSPORT=streamable-http
MCP_HOST=0.0.0.0
MCP_PORT=8080

LOG_LEVEL=INFO
```

> `SC_HOST` is the hostname only — the server builds `https://host:port/rest`.

### 2. Run with Docker Compose

```yaml
services:
  tenable-sc-mcp:
    image: ghcr.io/sparksbenjamin/tenable.sc-mcp:latest
    container_name: tenable-sc-mcp
    restart: unless-stopped
    ports:
      - "${MCP_PORT:-8080}:${MCP_PORT:-8080}"
    environment:
      SC_HOST: ${SC_HOST}
      SC_USERNAME: ${SC_USERNAME}
      SC_PASSWORD: ${SC_PASSWORD}
      SC_PORT: ${SC_PORT:-443}
      SC_VERIFY_SSL: ${SC_VERIFY_SSL:-true}
      SC_TIMEOUT: ${SC_TIMEOUT:-30}
      MCP_TRANSPORT: streamable-http
      MCP_HOST: 0.0.0.0
      MCP_PORT: ${MCP_PORT:-8080}
      LOG_LEVEL: ${LOG_LEVEL:-INFO}
```

```bash
docker compose up -d
```

MCP endpoint: `http://localhost:8080/mcp`

### 3. Configure your MCP client

```json
{
  "mcp": {
    "tenable-sc": {
      "type": "remote",
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

For local stdio use:

```json
{
  "mcpServers": {
    "tenable-sc": {
      "command": "python",
      "args": ["main.py"],
      "env": {
        "SC_HOST": "securitycenter.example.com",
        "SC_USERNAME": "svc_mcp",
        "SC_PASSWORD": "super-secret-password",
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SC_HOST` | ✅ | — | Tenable.sc hostname (no scheme) |
| `SC_USERNAME` | ✅ | — | API user |
| `SC_PASSWORD` | ✅ | — | API password |
| `SC_PORT` | | `443` | HTTPS port |
| `SC_VERIFY_SSL` | | `true` | Verify TLS certificates |
| `SC_TIMEOUT` | | `30` | Request timeout (seconds) |
| `MCP_TRANSPORT` | | `streamable-http` | `stdio` \| `streamable-http` \| `sse` |
| `MCP_HOST` | | `0.0.0.0` | HTTP bind address |
| `MCP_PORT` | | `8080` | HTTP port |
| `MCP_ALLOWED_HOSTS` | | bind host | Comma-separated Host header allowlist (DNS-rebinding protection) |
| `MCP_STATELESS` | | `false` | Stateless streamable-http mode |
| `LOG_LEVEL` | | `INFO` | Logging verbosity |

---

## Available MCP Tools

### Generic resource operations

| Tool | Description |
|---|---|
| `tsc_current_user` | Authenticated user, org, and permissions |
| `tsc_current_user_org` | Session user's organization |
| `tsc_list` | List objects from any resource family (scan, asset_list, policy, report, user, ...) |
| `tsc_get` | Fetch one object by id |
| `tsc_create` | Create an object |
| `tsc_update` | Update (PATCH) an object |
| `tsc_delete` | Delete an object |
| `tsc_request` | Raw REST passthrough for anything not specialized |

Resource families supported by `tsc_list`/`tsc_get`/`tsc_create`/`tsc_update`/`tsc_delete`:
`alert, asset_list, audit_file, credential, dashboard, group, organization,
query, recast_risk_rule, accept_risk_rule, report, report_definition,
repository, role, scan, scan_zone, scanner, scan_result, ticket, user,
was_scan, agent_scan, agent_group, agent_results_sync, ldap, saml, pub_site,
notification, freeze_window, passive_scanner, policy, mdm, attribute_set`

### Analysis

| Tool | Description |
|---|---|
| `tsc_analyze` | Run analysis queries (vuln, event, user, mobile, scLog) with filters, sorting, pagination |

Filter syntax: `severity=4`, `name~contains~prod`, JSON arrays, or nested
asset combos (`{"or": [1, 2]}`).

### File transfer

| Tool | Description |
|---|---|
| `tsc_upload_file` | Upload a file (base64), returns the SC filename token |
| `tsc_download` | Download reports, scan results, policies, audit files (base64) |

### Scan operations

| Tool | Description |
|---|---|
| `tsc_scan_launch` | Launch a scan with optional overrides (targets, timeout, ...) |
| `tsc_scan_copy` | Copy a scan definition |
| `tsc_scan_result_stop/pause/resume/copy` | Control running scan instances |
| `tsc_scan_result_email` | Email a scan result |
| `tsc_scan_result_reimport` | Re-import a result into its repository |
| `tsc_scan_result_import_file` | Import an uploaded .nessus file |
| `tsc_agent_scan_launch` | Launch an agent scan |
| `tsc_was_scan_launch` | Launch a web app scan |
| `tsc_scan_zone_list` | List scan zones |

### Assets, organizations, credentials

| Tool | Description |
|---|---|
| `tsc_asset_list_export/import` | Move asset list definitions |
| `tsc_asset_list_refresh` | Recompute dynamic lists |
| `tsc_asset_list_share` | Share with groups |
| `tsc_asset_list_test_ldap` | Validate an LDAP query |
| `tsc_hosts_search` | Search host inventory |
| `tsc_hosts_uuid` | Host record by UUID |
| `tsc_organization_risk_rules` | Accept/recast rules per org |
| `tsc_organization_user_list` | Users in an org |
| `tsc_org_security_manager_list/authorize` | Multi-SC security managers |
| `tsc_credential_share` | Share a scan credential |

### Policies, audit files, plugins, feeds

| Tool | Description |
|---|---|
| `tsc_policy_copy/share/import` | Policy lifecycle |
| `tsc_policy_template_list/details` | Browse policy templates |
| `tsc_audit_file_refresh/share` | Audit file lifecycle |
| `tsc_audit_file_template_categories/details` | Browse audit templates |
| `tsc_plugin_details/list` | Plugin info |
| `tsc_plugin_family_list/plugins` | Browse plugin families |
| `tsc_feed_status/update/process` | Feed management (online + offline) |

### Repositories and risk rules

| Tool | Description |
|---|---|
| `tsc_repository_sync` | Sync remote repository |
| `tsc_repository_remote_authorize/fetch` | Multi-SC repository movement |
| `tsc_repository_device_info` | Mobile device info |
| `tsc_repository_asset_intersections` | Asset overlaps |
| `tsc_accept_risk_rule_create/apply/list` | Accept risk rules |
| `tsc_recast_risk_rule_create/apply/list` | Recast risk rules |

### Reports and dashboards

| Tool | Description |
|---|---|
| `tsc_report_definition_launch/copy/import` | Report definitions |
| `tsc_report_email/stop/copy` | Report instances |
| `tsc_report_template_list/categories/details` | Browse report templates |
| `tsc_dashboard_import/export/copy/share` | Dashboard lifecycle |
| `tsc_dashboard_template_categories/details` | Browse dashboard templates |

### System and operations

| Tool | Description |
|---|---|
| `tsc_status` | Session status and capabilities |
| `tsc_system_status` | System diagnostics summary |
| `tsc_system_diagnostics` / `..._generate` | Full diagnostics |
| `tsc_system_locale` / `tsc_system_locales` | Locale management |
| `tsc_license_info` | Licensing info |
| `tsc_job_details/kill` | Background jobs |
| `tsc_alert_execute` | Fire an alert now |
| `tsc_scanner_update_status` / `tsc_scanner_health` | Scanner ops |
| `tsc_scanner_agent_scans_query` | Agent scan matching |
| `tsc_ticket_list` | Tickets |

---

## Example Prompts

```text
Show me critical vulnerabilities discovered in the last 7 days
```

```text
List all repositories and their IDs
```

```text
Launch the weekly external scan
```

```text
Show me the top vulnerable assets by severity
```

```text
Accept plugin 19506 in repository 1 for 90 days with a comment
```

---

## Security Notes

> [!WARNING]
> This MCP server inherits the permissions of the configured Tenable.sc API user.
> Use a dedicated least-privilege service account.

> [!CAUTION]
> Remote HTTP mode does not provide built-in authentication.
> Restrict access using VPNs, reverse proxies, firewalls, or SSH tunnels.
> DNS-rebinding protection is enabled by default; set `MCP_ALLOWED_HOSTS`
> to the exact Host headers clients will send.

---

## Local Development

```bash
git clone https://github.com/sparksbenjamin/tenable.sc-mcp.git
cd tenable.sc-mcp
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest pytest-asyncio
python -m pytest tests/ -v     # 95 tests, no live SC needed
MCP_TRANSPORT=stdio python main.py
```

---

## Troubleshooting

### SSL Errors

For lab or self-signed environments:

```env
SC_VERIFY_SSL=false
```

### Browser Access Errors

Opening `/mcp` directly in a browser may show protocol errors. This is
expected — the endpoint is intended for MCP-compatible clients.

### Session exhaustion

The server logs in once and reuses the session; if SC reports the max
concurrent sessions it automatically re-authenticates with
`releaseSession=true`.

---

## Roadmap

- OAuth support for the HTTP transport
- Tool-level RBAC filtering (expose only the families the account may use)
- Streaming analysis queries
- Audit logging improvements

---

## License

MIT — see [LICENSE](LICENSE).
