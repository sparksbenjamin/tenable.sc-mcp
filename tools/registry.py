"""
Tenable.sc REST endpoint registry.

Single source of truth for the resource families exposed by the generic
list/get/create/update/delete tools. Paths are doc-style templates
('/scan/{id}') expanded by helpers.format_path.

Verbs marked with a '?' are known from pyTenable usage but not spelled out
in the doc page header — the registry records only well-attested verbs.
"""

from __future__ import annotations

# resource key -> {
#   collection:   '/family'                     (list / create)
#   member:       '/family/{id}'                (get / patch / delete)
#   get/post/patch/delete: which verbs the API documents for each shape
#   describe:     human blurb for tool docs
# }
RESOURCES: dict[str, dict] = {
    "alert": {
        "collection": "/alert",
        "member": "/alert/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Alerts that trigger on query conditions (email, SNMP, etc.)",
    },
    "asset_list": {
        "collection": "/asset",
        "member": "/asset/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Static and dynamic asset lists (IPs, DNS names, LDAP queries)",
    },
    "audit_file": {
        "collection": "/auditFile",
        "member": "/auditFile/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Audit files (.audit) used by compliance scans",
    },
    "credential": {
        "collection": "/credential",
        "member": "/credential/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Scan credentials (SSH, Windows, database, etc.)",
    },
    "dashboard": {
        "collection": "/dashboard",
        "member": "/dashboard/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Dashboard tabs; components live under a dashboard",
    },
    "group": {
        "collection": "/group",
        "member": "/group/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "User groups",
    },
    "organization": {
        "collection": "/organization",
        "member": "/organization/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Organizations (multi-tenancy)",
    },
    "query": {
        "collection": "/query",
        "member": "/query/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Saved analysis queries (filters reused by dashboards/alerts)",
    },
    "recast_risk_rule": {
        "collection": "/recastRiskRule",
        "member": "/recastRiskRule/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Recast risk rules (severity override)",
    },
    "accept_risk_rule": {
        "collection": "/acceptRiskRule",
        "member": "/acceptRiskRule/{id}",
        "get": True, "post": True, "patch": False, "delete": True,
        "describe": "Accept risk rules (suppress a finding as accepted)",
    },
    "report": {
        "collection": "/report",
        "member": "/report/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Generated report instances (from a report definition launch)",
    },
    "report_definition": {
        "collection": "/reportDefinition",
        "member": "/reportDefinition/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Report definitions (the report 'recipe')",
    },
    "repository": {
        "collection": "/repository",
        "member": "/repository/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "get_params": {"type": True},
        "describe": "Scan data repositories",
    },
    "role": {
        "collection": "/role",
        "member": "/role/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "User roles and their permissions",
    },
    "scan": {
        "collection": "/scan",
        "member": "/scan/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Scan definitions (schedule, targets, policy)",
    },
    "scan_zone": {
        "collection": "/zone",
        "member": "/zone/{id}",
        "get": True,
        "post": True, "patch": True, "delete": True,
        "describe": "Scan zones (groups of scanners)",
    },
    "scanner": {
        "collection": "/scanner",
        "member": "/scanner/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Managed scanners",
    },
    "scan_result": {
        "collection": "/scanResult",
        "member": "/scanResult/{id}",
        "get": True, "post": False, "patch": False, "delete": True,
        "describe": "Scan results / instances (history of runs)",
    },
    "ticket": {
        "collection": "/ticket",
        "member": "/ticket/{id}",
        "get": True, "post": True, "patch": True, "delete": False,
        "describe": "Tickets for tracking vulnerability remediation",
    },
    "user": {
        "collection": "/user",
        "member": "/user/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Users",
    },
    "was_scan": {
        "collection": "/wasScan",
        "member": "/wasScan/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Web application scanning (WAS) scans",
    },
    "was_store": {
        "collection": "/wasStore",
        "member": "/wasStore/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "WAS configuration/store entries",
    },
    "agent_scan": {
        "collection": "/agentScan",
        "member": "/agentScan/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Agent scans (Nessus Agent scan definitions)",
    },
    "agent_group": {
        "collection": "/agentGroup",
        "member": "/agentGroup/{agentScanID}",
        "get": True, "post": False, "patch": False, "delete": True,
        "describe": "Agent groups per agent scan",
    },
    "agent_results_sync": {
        "collection": "/agentResultsSync",
        "member": "/agentResultsSync/{id}",
        "get": True, "post": False, "patch": False, "delete": True,
        "describe": "Agent results sync jobs",
    },
    "ldap": {
        "collection": "/ldap",
        "member": "/ldap/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "LDAP authentication servers",
    },
    "saml": {
        "collection": "/saml",
        "member": "/saml/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "SAML authentication configurations",
    },
    "pub_site": {
        "collection": "/pubSite",
        "member": "/pubSite/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Publishing sites for reports",
    },
    "notification": {
        "collection": "/notification",
        "member": "/notification/{id}",
        "get": True, "post": False, "patch": True, "delete": True,
        "describe": "In-app notifications",
    },
    "freeze_window": {
        "collection": "/freeze",
        "member": "/freeze/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Scan freeze windows (blackouts)",
    },
    "passive_scanner": {
        "collection": "/passivescanner",
        "member": "/passivescanner/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Passive vulnerability scanners",
    },
    "policy": {
        "collection": "/policy",
        "member": "/policy/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Scan policies (Nessus policy settings)",
    },
    "mdm": {
        "collection": "/mdm",
        "member": "/mdm/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "MDM configurations",
    },
    "attribute_set": {
        "collection": "/attributeSet",
        "member": "/attributeSet/{id}",
        "get": True, "post": True, "patch": True, "delete": True,
        "describe": "Generic attribute sets (arbitrary org-scoped key/value data)",
    },
}
