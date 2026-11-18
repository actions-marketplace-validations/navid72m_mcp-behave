"""SARIF (Static Analysis Results Interchange Format) v2.1.0 exporter for mcp-behave.

Produces OASIS SARIF v2.1.0 compliant JSON reports compatible with GitHub Code Scanning,
GitLab SAST, and standard vulnerability management dashboards.
"""
from pathlib import Path
from typing import Any, Dict, List, Optional
from . import __version__

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

RULES = {
    "MCP001": {
        "id": "MCP001",
        "name": "UndeclaredNetworkEgress",
        "shortDescription": {"text": "Undeclared network egress detected at runtime"},
        "fullDescription": {"text": "The MCP server opened network socket connections during execution, violating local/offline declarations or undeclared network scope."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/data-exfiltration/",
        "properties": {"tags": ["security", "network-egress", "csa-ttp"]}
    },
    "MCP002": {
        "id": "MCP002",
        "name": "SensitiveFileAccess",
        "shortDescription": {"text": "Access to confidential file or credentials detected"},
        "fullDescription": {"text": "The MCP server read sensitive local system paths such as SSH keys, cloud credentials, or environment files."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/privilege-access-control/",
        "properties": {"tags": ["security", "credential-access", "csa-ttp"]}
    },
    "MCP003": {
        "id": "MCP003",
        "name": "SubprocessExecution",
        "shortDescription": {"text": "Subprocess spawned by MCP server"},
        "fullDescription": {"text": "The MCP server executed an external system binary or subshell."},
        "defaultConfiguration": {"level": "note"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/privilege-access-control/",
        "properties": {"tags": ["security", "execution"]}
    },
    "MCP004": {
        "id": "MCP004",
        "name": "ManifestRugPull",
        "shortDescription": {"text": "Declared tool manifest changed between runs (rug-pull)"},
        "fullDescription": {"text": "The advertised tool definitions or schemas changed compared to historical runs for this server, indicating potential capability mutation or rug-pull attacks."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/tool-poisoning/tool-mutation/",
        "properties": {"tags": ["security", "rug-pull", "integrity", "csa-ttp"]}
    },
    "MCP005": {
        "id": "MCP005",
        "name": "CovertChannelANSI",
        "shortDescription": {"text": "ANSI terminal escape sequences in metadata or output"},
        "fullDescription": {"text": "The server includes ANSI escape sequences in tool descriptions or responses, creating terminal manipulation or display injection risks."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/prompt-injection/tool-description-poisoning/",
        "properties": {"tags": ["security", "covert-channel", "ansi-escape", "csa-ttp"]}
    },
    "MCP006": {
        "id": "MCP006",
        "name": "CovertChannelUnicode",
        "shortDescription": {"text": "Invisible Unicode or BiDi override characters detected"},
        "fullDescription": {"text": "The server includes zero-width spaces, BiDi overrides, or tag characters in metadata or responses for hidden prompt injection."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/tool-poisoning/metadata-prompt-injection/",
        "properties": {"tags": ["security", "covert-channel", "unicode", "csa-ttp"]}
    },
    "MCP007": {
        "id": "MCP007",
        "name": "PromptInjectionDirective",
        "shortDescription": {"text": "Prompt injection directive in metadata or output"},
        "fullDescription": {"text": "Direct instructions attempting to override LLM system prompts or hijack agent control flow were detected."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/prompt-injection/",
        "properties": {"tags": ["security", "prompt-injection", "csa-ttp"]}
    },
    "MCP008": {
        "id": "MCP008",
        "name": "ExternalImageExfiltration",
        "shortDescription": {"text": "External image link in tool output (client-side exfiltration)"},
        "fullDescription": {"text": "A tool response contains Markdown or HTML external image references that cause client-side applications to issue automatic HTTP GET exfiltration requests."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/data-exfiltration/",
        "properties": {"tags": ["security", "data-exfiltration", "csa-ttp"]}
    },
    "MCP009": {
        "id": "MCP009",
        "name": "HardcodedSecretConfig",
        "shortDescription": {"text": "Hardcoded secret or credential in client configuration"},
        "fullDescription": {"text": "An MCP client configuration contains plaintext API keys or credentials in environment variables or arguments."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/hardening/credentials/",
        "properties": {"tags": ["security", "hardcoded-secret"]}
    },
    "MCP010": {
        "id": "MCP010",
        "name": "OverprivilegedMountConfig",
        "shortDescription": {"text": "Over-privileged filesystem mount in client configuration"},
        "fullDescription": {"text": "An MCP server is configured with root filesystem or confidential home directory access."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/privilege-access-control/excessive-tool-permissions/",
        "properties": {"tags": ["security", "excessive-permissions"]}
    },
    "MCP011": {
        "id": "MCP011",
        "name": "ReadOnlyHintMismatch",
        "shortDescription": {"text": "Mutating or destructive tool advertises readOnlyHint"},
        "fullDescription": {"text": "A tool that deletes, writes, or modifies state advertises readOnlyHint: true, causing AI clients to auto-approve executions without user confirmation."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/privilege-access-control/",
        "properties": {"tags": ["security", "confused-deputy", "auto-approval-bypass"]}
    },
    "MCP012": {
        "id": "MCP012",
        "name": "DestructiveActionConfirmation",
        "shortDescription": {"text": "Destructive tool lacks confirmation or scope argument"},
        "fullDescription": {"text": "A tool that performs deletion or destructive actions has no explicit confirmation parameter (e.g. confirm, force, dry_run)."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/hardening/",
        "properties": {"tags": ["security", "destructive-action", "safety"]}
    },
    "MCP013": {
        "id": "MCP013",
        "name": "PathTraversalArgument",
        "shortDescription": {"text": "Unconstrained filesystem path argument"},
        "fullDescription": {"text": "A file or path parameter accepts arbitrary strings without pattern or enum constraints, inviting path traversal."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/path-traversal/",
        "properties": {"tags": ["security", "path-traversal"]}
    },
    "MCP014": {
        "id": "MCP014",
        "name": "SSRFArgument",
        "shortDescription": {"text": "Unconstrained URL argument enables SSRF"},
        "fullDescription": {"text": "A URL parameter accepts arbitrary external endpoints without destination host allowlists or schema pattern constraints."},
        "defaultConfiguration": {"level": "note"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/data-exfiltration/",
        "properties": {"tags": ["security", "ssrf"]}
    },
    "MCP015": {
        "id": "MCP015",
        "name": "HardcodedSchemaSecret",
        "shortDescription": {"text": "Hardcoded credential in tool schema default or example"},
        "fullDescription": {"text": "A tool input schema contains real API tokens or secrets in default, const, or example values."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/hardening/credentials/",
        "properties": {"tags": ["security", "hardcoded-secret"]}
    },
    "MCP016": {
        "id": "MCP016",
        "name": "SensitiveResourceURI",
        "shortDescription": {"text": "Resource surfaces sensitive file or credential"},
        "fullDescription": {"text": "An advertised resource URI points directly at confidential credentials or system files."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/privilege-access-control/",
        "properties": {"tags": ["security", "credential-exposure"]}
    },
    "MCP017": {
        "id": "MCP017",
        "name": "DuplicateToolName",
        "shortDescription": {"text": "Duplicate tool name enables tool shadowing"},
        "fullDescription": {"text": "Multiple tools share the exact same name, making invocation ambiguous and allowing malicious tools to shadow trusted ones."},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/tool-poisoning/",
        "properties": {"tags": ["security", "shadowing", "hygiene"]}
    },
    "MCP018": {
        "id": "MCP018",
        "name": "CrossToolChaining",
        "shortDescription": {"text": "Description directs cross-tool chaining"},
        "fullDescription": {"text": "A tool description instructs the model to call other tools, smuggling tool-shadowing or execution hijacking directives."},
        "defaultConfiguration": {"level": "note"},
        "helpUri": "https://modelcontextprotocol-security.io/ttps/prompt-injection/",
        "properties": {"tags": ["security", "prompt-injection", "chaining"]}
    },
}


def classify_rule_id(severity: str, message: str) -> str:
    """Map an mcp-behave finding message to a formal SARIF rule ID."""
    msg = message.lower()
    if "readonlyhint" in msg:
        return "MCP011"
    if "destructive action" in msg or "confirmation or scoping" in msg:
        return "MCP012"
    if "path traversal" in msg or "unconstrained filesystem path" in msg:
        return "MCP013"
    if "ssrf" in msg or "caller-controlled url" in msg:
        return "MCP014"
    if "schema default/examples" in msg or "schema default" in msg:
        return "MCP015"
    if "surfaces sensitive system path" in msg or ("resource" in msg and "sensitive" in msg):
        return "MCP016"
    if "duplicate tool name" in msg:
        return "MCP017"
    if "cross-tool chaining" in msg:
        return "MCP018"
    if "network egress" in msg:
        return "MCP001"
    if "sensitive path" in msg or "id_rsa" in msg or "id_ed25519" in msg or ".ssh" in msg:
        return "MCP002"
    if "spawned subprocess" in msg:
        return "MCP003"
    if "declared surface changed" in msg or "rug-pull" in msg:
        return "MCP004"
    if "ansi escape" in msg:
        return "MCP005"
    if "zero-width" in msg or "invisible" in msg or "bidi" in msg or "tag characters" in msg:
        return "MCP006"
    if "prompt injection" in msg:
        return "MCP007"
    if "external image" in msg:
        return "MCP008"
    if "hardcoded" in msg:
        return "MCP009"
    if "over-privileged" in msg or "sensitive directory mount" in msg:
        return "MCP010"
    return "MCP001" if severity == "HIGH" else "MCP003"


def severity_to_sarif_level(sev: str) -> str:
    """Map mcp-behave severity (HIGH, INFO) to SARIF levels (error, warning, note)."""
    s = sev.upper()
    if s == "HIGH":
        return "error"
    elif s == "WARNING":
        return "warning"
    return "note"


def find_artifact_uri(server_cmd: Optional[List[str]]) -> str:
    """Identify the target file path from the command tokens if present."""
    if not server_cmd:
        return "manifest.json"
    for token in server_cmd:
        if token.endswith((".py", ".js", ".ts", ".json", ".sh", ".rb", ".go", ".rs")):
            return token
    for token in server_cmd:
        if not token.startswith("-"):
            return token
    return "manifest.json"


def to_sarif(report_data: Dict[str, Any], artifact_override: Optional[str] = None) -> Dict[str, Any]:
    """Convert an mcp-behave audit JSON report to a valid OASIS SARIF v2.1.0 document."""
    server_cmd = report_data.get("server_cmd") or []
    target_uri = artifact_override or find_artifact_uri(server_cmd)
    raw_findings = report_data.get("findings") or []

    results = []
    used_rule_ids = set()

    for item in raw_findings:
        sev = item.get("severity", "INFO")
        msg = item.get("message", "")
        rule_id = classify_rule_id(sev, msg)
        used_rule_ids.add(rule_id)
        level = severity_to_sarif_level(sev)

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": msg
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target_uri
                        },
                        "region": {
                            "startLine": 1
                        }
                    }
                }
            ]
        })

    # Filter rules list to rules relevant to mcp-behave (include all standard rules for validation)
    rules_list = list(RULES.values())

    run_obj: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "mcp-behave",
                "version": __version__,
                "informationUri": "https://github.com/navid72m/mcp-behave",
                "rules": rules_list,
            }
        },
        "results": results,
    }

    if "scorecard" in report_data:
        run_obj["properties"] = {
            "mcpSecurityScore": report_data["scorecard"].get("score"),
            "mcpSecurityGrade": report_data["scorecard"].get("grade"),
            "mcpPassed": report_data["scorecard"].get("passed"),
        }

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run_obj]
    }

    return sarif_doc


def configs_to_sarif(scan_data: Dict[str, Any], audit_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Convert scan_all_configs and audit_configured_servers data into an OASIS SARIF v2.1.0 document."""
    results = []
    servers = {f"{s['client']}::{s['name']}": s for s in scan_data.get("servers", [])}

    # 1. Config findings
    for skey, findings in scan_data.get("config_findings", {}).items():
        server = servers.get(skey, {})
        config_path = server.get("config_path", "config.json")
        for sev, msg in findings:
            rule_id = classify_rule_id(sev, msg)
            level = severity_to_sarif_level(sev)
            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": msg},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": config_path},
                        "region": {"startLine": 1}
                    }
                }]
            })

    # 2. Behavioral audit findings
    if audit_data:
        for skey, a_info in audit_data.items():
            server = servers.get(skey, {})
            server_cmd = server.get("full_command") or []
            target_uri = find_artifact_uri(server_cmd)
            for f in a_info.get("findings", []):
                sev = f.get("severity", "INFO")
                msg = f.get("message", "")
                rule_id = classify_rule_id(sev, msg)
                level = severity_to_sarif_level(sev)
                results.append({
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": msg},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": target_uri},
                            "region": {"startLine": 1}
                        }
                    }]
                })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcp-behave",
                    "version": __version__,
                    "informationUri": "https://github.com/navid72m/mcp-behave",
                    "rules": list(RULES.values()),
                }
            },
            "results": results,
        }]
    }
