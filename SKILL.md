---
name: tenable-sc-mcp
description: Use the Tenable.sc MCP tools for vulnerability, asset, repository, scan, analysis, and report workflows, with careful handling of changes and exports.
tags:
- mcp
- tenable
- security
related_skills:
- native-mcp
title: SKILL
last_updated: '2026-10-13'
---

# Tenable.sc MCP

Use this skill when the user wants to query or operate Tenable.sc through the configured `tenable.sc-mcp` server. It helps translate plain-language vulnerability-management requests into the server's discovered MCP tools and explain their results.

## Easy invocation

The user can ask in ordinary language, for example:

- “Show critical vulnerabilities found in the last seven days.”
- “List Tenable.sc repositories and their IDs.”
- “Compare the most vulnerable assets by severity.”
- “Launch the weekly external scan.”
- “Export the report for repository 12.”
- “Why are my Tenable.sc MCP tools unavailable?”

## Start with the live tool schema

The server documents these tools:

- `tsc_current_user` — identify the authenticated Tenable.sc user.
- `tsc_list`, `tsc_get` — list and retrieve resources.
- `tsc_analyze` — execute analysis queries.
- `tsc_create`, `tsc_update`, `tsc_delete` — change resources.
- `tsc_download`, `tsc_upload_file` — transfer report/export files.
- `tsc_request` — generic REST API passthrough.

Use the tools and argument schemas actually exposed by MCP discovery. Do not assume resource names, filter syntax, endpoint paths, object IDs, or argument shapes from a prompt or an old example. If schema details are missing, inspect the available tool description or ask for the necessary input rather than guessing.

## Workflow

1. **Identify the task.** Determine whether the user wants information, analysis, a scan or configuration change, or a file transfer.
2. **Establish context.** When account or instance identity matters, use `tsc_current_user`. Resolve repositories, scans, assets, and reports to their actual IDs using read tools before acting.
3. **Query narrowly.** Prefer `tsc_list`, `tsc_get`, or `tsc_analyze` with the smallest useful date range, repository, severity, or asset filters. Do not imply the dataset is complete if a query is paginated, filtered, or returned partial results.
4. **Review before mutation.** For scan launches, creation, updates, deletion, uploads, or generic REST writes, check the exact target and effect. Perform them only when the user clearly requested that specific action. For ambiguous or potentially disruptive changes, summarize the proposed action and ask first.
5. **Verify and report.** Where practical, retrieve the changed object's status or details after a mutation. Report the actual result and any partial failure; do not fabricate findings, counts, or completion status.

## Safety and data handling

- The MCP server inherits the permissions of its configured Tenable.sc API account. Do not treat tool availability as user intent or sufficient reason to make changes.
- Prefer read-only queries by default. A broad phrase like “look into” or “help with” authorizes investigation, not scan launches or configuration changes.
- Before launching a scan, verify the scan name or ID and scope. Do not broaden scan scope or launch repeated scans to work around errors.
- Before `tsc_update` or `tsc_delete`, resolve the exact object and summarize the material change. Delete only when the user explicitly asks to delete that specific object; if identity or impact is uncertain, clarify first.
- Treat generic `tsc_request` as capable of arbitrary API operations. Use it only when the endpoint and method are understood and match the user's request. Do not use it to bypass a rejected or unavailable specialized tool.
- Handle vulnerability data, reports, and exports as potentially sensitive. Download or upload only the requested material, avoid exposing unnecessary host identifiers or findings in chat, and do not transmit files to unapproved destinations.
- Never reveal passwords, API tokens, session cookies, or credential-bearing configuration. Do not turn off TLS verification as a routine fix.

## Reporting results

For vulnerability queries, state the time window, repository or scope filters, severity criteria, and returned count when the tool provides them. Summarize notable results and mention pagination or other limits. For mutations, state the object and action, then include the verification result. Clearly label conclusions as interpretation when they go beyond returned data.

## Troubleshooting

- **No Tenable.sc tools discovered:** check whether the MCP server is present in the active client's tool list. If absent, its configuration or connection must be fixed and the client may need restarting. For Hermes MCP configuration workflow, consult `native-mcp`.
- **Authentication or permission error:** report the returned error and ask an administrator to check the configured service account and its least-privilege permissions. Do not request secrets in chat.
- **TLS or connection error:** check the configured host, port, network route, and certificate trust. Preserve SSL verification unless the operator has a deliberate, scoped lab configuration.
- **Unexpected API behavior:** inspect the discovered schema and returned error, then use the documented specialized tool if it fits. Do not retry a write blindly; determine whether the first request took effect.

## Source

- [Tenable.sc MCP repository](https://github.com/sparksbenjamin/tenable.sc-mcp) — tool list, transports, deployment options, and security notes.
