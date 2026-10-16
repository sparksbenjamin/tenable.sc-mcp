---
name: tenable-sc-mcp
description: Tenable.sc (SecurityCenter) MCP server exposing the full REST API to AI agents — 91 tools for vulnerability analysis, scan lifecycle, asset and risk management, reporting, and platform administration. Use when an agent needs to query or operate Tenable.sc.
license: MIT
---

# Tenable.sc MCP Server — Agent Skill

This skill teaches an agent to use the **tenable.sc-mcp** MCP server, which
wraps the Tenable.sc REST API (`https://<host>/rest/...`) behind safe,
typed MCP tools.

## Environment (required)

The server reads credentials from env vars at startup:

```text
SC_HOST, SC_USERNAME, SC_PASSWORD       # required
SC_PORT=443, SC_VERIFY_SSL, SC_TIMEOUT  # optional
```

The agent does not handle auth; the server logs in once, caches the token,
and re-authenticates on expiry.

## Tool map — what to call, when

### Discovery first

1. `tsc_current_user` — who am I, which org, what permissions
2. `tsc_status` — SC version, capabilities, licensing
3. `tsc_list` with the resource families — orient before acting

### Generic CRUD (most resources)

`tsc_list`, `tsc_get`, `tsc_create`, `tsc_update`, `tsc_delete` operate on
any registered family:

```text
alert, asset_list, audit_file, credential, dashboard, group, organization,
query, recast_risk_rule, accept_risk_rule, report, report_definition,
repository, role, scan, scan_zone, scanner, scan_result, ticket, user,
was_scan, agent_scan, agent_group, agent_results_sync, ldap, saml, pub_site,
notification, freeze_window, passive_scanner, policy, mdm, attribute_set
```

`body` accepts a JSON object or string; `fields` takes comma-separated
field names to trim payloads.

### Analysis (the workhorse)

`tsc_analyze` runs the SC analysis engine:

- `analysis_type`: `vuln` | `event` | `mobile` | `user` | `scLog`
- `tool`: e.g. `vulndetails` (default), `sumip`, `sumseverity`...
- Filters: `severity=4`, `name~contains~prod`, JSON arrays, or asset
  combos (`{"or": [1, 2]}`)
- Sort/paginate with `sort_field`, `sort_dir`, `limit`, `offset`
- Large result sets auto-truncate at ~200k chars with a notice

### Scans

- Launch: `tsc_scan_launch` (network), `tsc_agent_scan_launch` (agent),
  `tsc_was_scan_launch` (web app) — overrides for targets, policy, creds
- Control: `tsc_scan_result_stop/pause/resume`
- Move data: `tsc_scan_result_copy/email/reimport`,
  `tsc_scan_result_import_file` (upload .nessus first)

### Risk remediation

- Accept: `tsc_accept_risk_rule_create` → `tsc_accept_risk_rule_apply`
- Recast: `tsc_recast_risk_rule_create` → `tsc_recast_risk_rule_apply`
- Scope by asset list, repository, plugin; set expiry in epoch seconds

### Reports

- `tsc_report_definition_launch` generates now
- `tsc_download` fetches the finished artifact (PDF/HTML/CSV)
- `tsc_report_email` distributes

### Files

- `tsc_upload_file` (base64) → returns SC filename token → feed it to
  import tools (`tsc_policy_import`, `tsc_dashboard_import`, ...)
- `tsc_download` returns base64 + content type

### Escape hatch

Anything not specialized: `tsc_request(method, path, body)` — direct REST
passthrough with automatic auth.

## Conventions

- **IDs are strings** in SC responses — compare as strings, not ints.
- **Fields trimming**: pass `fields="id,name"` to lists for lean output.
- **Pagination**: `offset` + `limit`; large pages auto-truncate.
- **Destructive ops** carry `destructiveHint` in their tool annotations.
- **Errors** come back as ToolError with the SC error message embedded —
  read it before retrying blindly.

## Common recipes

**Top 10 critical vulns:**

```json
{"analysis_type": "vuln", "tool": "sumip",
 "filters": "severity=4", "limit": 10, "sort_field": "severity"}
```

**Accept a finding for 90 days:**

```json
{"plugin_id": "19506", "repositories": "1",
 "expires": 1893456000, "comments": "compensating control"}
```

**Export then email a report:**

```json
{"report_definition_id": 42}
```

then `tsc_download`, then `tsc_report_email`.

## Pitfalls

- **hosts endpoints use a different filter format** — property/operator/value
  in an `{"and": [...]}` object (see `tsc_hosts_search`), not the analysis
  filterName shape.
- **`.nessus` imports are two-step**: `tsc_upload_file` first, then
  `tsc_scan_result_import_file` with the returned filename.
- **Offline feed updates** need `tsc_upload_file` + `tsc_feed_process`.
- **`tsc_request` paths** don't include `/rest/` — the server adds it.
