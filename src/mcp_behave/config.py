"""Configuration and rule suppression policy loader for mcp-behave.

Loads project-level configuration (.mcpbehaverc.json, .mcpbehaverc, mcpbehave.config.json)
or an explicitly specified --config file, and applies rule suppression, severity overrides,
and ignore patterns to findings.
"""
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CONFIG_FILENAMES = (
    ".mcpbehaverc.json",
    ".mcpbehaverc",
    "mcpbehave.config.json",
)

DEFAULT_CONFIG: Dict[str, Any] = {
    "fail_on": "high",
    "disabled_rules": [],
    "severity_overrides": {},
    "ignore": [],
    "timeout": 15.0,
    "no_dns": False,
    "allowed_commands": [],
}


def find_config_file(start_path: Optional[os.PathLike | str] = None) -> Optional[Path]:
    """Search for a config file starting at start_path (or cwd) and walking up parent directories."""
    current = Path(start_path or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent

    for directory in [current, *current.parents]:
        for fname in CONFIG_FILENAMES:
            candidate = directory / fname
            if candidate.is_file():
                return candidate
    return None


def load_config(config_path: Optional[os.PathLike | str] = None, start_path: Optional[os.PathLike | str] = None) -> Dict[str, Any]:
    """Load configuration from an explicit path or search upwards.

    Returns a normalized dictionary containing default values merged with file configuration.
    """
    path = Path(config_path) if config_path else find_config_file(start_path)
    if not path or not path.exists():
        return dict(DEFAULT_CONFIG)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        import sys
        print(f"[config] warning: failed to parse config at {path}: {exc}", file=sys.stderr)
        return dict(DEFAULT_CONFIG)

    merged = dict(DEFAULT_CONFIG)
    if isinstance(data, dict):
        merged.update(data)
        # Handle camelCase aliases from MCP-audit / ESLint ecosystem
        if "disabledRules" in data and "disabled_rules" not in data:
            merged["disabled_rules"] = data["disabledRules"]
        if "severityOverrides" in data and "severity_overrides" not in data:
            merged["severity_overrides"] = data["severityOverrides"]
        if "failOn" in data and "fail_on" not in data:
            merged["fail_on"] = data["failOn"]
        if "noDns" in data and "no_dns" not in data:
            merged["no_dns"] = data["noDns"]
        if "allowedCommands" in data and "allowed_commands" not in data:
            merged["allowed_commands"] = data["allowedCommands"]

    merged["_config_path"] = str(path)
    return merged


def filter_findings(findings: List[Tuple[str, str]], config: Optional[Dict[str, Any]] = None) -> List[Tuple[str, str]]:
    """Filter and remap finding severities according to config rules.

    - Drops findings matching any pattern in `disabled_rules` or `ignore`.
    - Remaps severity if a rule or pattern matches `severity_overrides`.
    """
    if not config:
        return list(findings)

    from . import sarif as sarif_mod

    disabled = [str(r).lower() for r in config.get("disabled_rules", [])]
    ignores = [str(i).lower() for i in config.get("ignore", [])]
    overrides = {str(k).lower(): str(v).upper() for k, v in config.get("severity_overrides", {}).items()}

    filtered: List[Tuple[str, str]] = []

    for sev, msg in findings:
        rule_id = sarif_mod.classify_rule_id(sev, msg).lower()
        msg_lower = msg.lower()

        # 1. Ignore checks: discard if message or location matches ignore list
        if any(ign in msg_lower for ign in ignores):
            continue

        # 2. Disabled rules check: discard if rule_id or keyword matches disabled_rules
        if any(d in rule_id or d in msg_lower for d in disabled):
            continue

        # 3. Severity overrides check: remap severity if matching
        effective_sev = sev
        for pattern, new_sev in overrides.items():
            if pattern in rule_id or pattern in msg_lower:
                effective_sev = new_sev
                break

        filtered.append((effective_sev, msg))

    return filtered
