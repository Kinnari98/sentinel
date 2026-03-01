#!/usr/bin/env python3
"""
Sentinel Analytic Rules - Deployment Script
Lukee YAML-säännöt ja deployaa ne Microsoft Sentineliin Azure CLI:n kautta.

Käyttö:
  python3 deploy_rules.py --workspace MyWorkspace --resource-group MyRG --rules-path ./analytic-rules
"""

import json
import subprocess
import sys
import argparse
import uuid
from pathlib import Path

try:
    import yaml
except ImportError:
    print("❌ PyYAML puuttuu. Aja: pip install pyyaml")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Duration-muunnos: "15m" → "PT15M", "1d" → "P1D" jne.
# ---------------------------------------------------------------------------
def to_iso8601(duration: str) -> str:
    if not duration:
        return "PT5M"
    duration = str(duration).strip().lower()
    if duration.startswith("p"):
        return duration.upper()
    if duration.endswith("d"):
        return f"P{duration[:-1]}D"
    if duration.endswith("h"):
        return f"PT{duration[:-1]}H"
    if duration.endswith("m"):
        return f"PT{duration[:-1]}M"
    if duration.endswith("s"):
        return f"PT{duration[:-1]}S"
    return "PT5M"


# ---------------------------------------------------------------------------
# Korjaa incidentConfiguration lookbackDuration ISO 8601 -muotoon
# ---------------------------------------------------------------------------
def fix_incident_config(incident_cfg: dict) -> dict:
    default = {
        "createIncident": True,
        "groupingConfiguration": {
            "enabled": False,
            "reopenClosedIncident": False,
            "lookbackDuration": "PT5H",
            "matchingMethod": "AllEntities",
            "groupByEntities": [],
            "groupByAlertDetails": [],
            "groupByCustomDetails": []
        }
    }
    if not incident_cfg:
        return default
    result = dict(incident_cfg)
    if "groupingConfiguration" in result:
        gc = dict(result["groupingConfiguration"])
        if "lookbackDuration" in gc:
            gc["lookbackDuration"] = to_iso8601(str(gc["lookbackDuration"]))
        result["groupingConfiguration"] = gc
    return result


# ---------------------------------------------------------------------------
# YAML → ARM-properties muunnos
# ---------------------------------------------------------------------------
def yaml_to_arm_properties(rule: dict) -> dict:
    props = {
        "displayName":      rule.get("name", "Unnamed Rule"),
        "description":      rule.get("description", ""),
        "severity":         rule.get("severity", "Medium"),
        "enabled":          rule.get("enabled", True),
        "query":            rule.get("query", ""),
        "queryFrequency":   to_iso8601(rule.get("queryFrequency", "5m")),
        "queryPeriod":      to_iso8601(rule.get("queryPeriod", "5m")),
        "triggerOperator":  rule.get("triggerOperator", "GreaterThan"),
        "triggerThreshold": rule.get("triggerThreshold", 0),
        "suppressionEnabled":  rule.get("suppressionEnabled", False),
        "suppressionDuration": to_iso8601(rule.get("suppressionDuration", "5h")),
        "tactics":    rule.get("tactics", []),
        "techniques": rule.get("relevantTechniques", []),
        "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
        "incidentConfiguration": fix_incident_config(rule.get("incidentConfiguration", {})),
    }

    if rule.get("entityMappings"):
        props["entityMappings"] = rule["entityMappings"]
    if rule.get("alertDetailsOverride"):
        props["alertDetailsOverride"] = rule["alertDetailsOverride"]
    if rule.get("customDetails"):
        props["customDetails"] = rule["customDetails"]

    return props


# ---------------------------------------------------------------------------
# Deployaa yksi sääntö Azure CLI:n kautta
# ---------------------------------------------------------------------------
def deploy_rule(rule: dict, workspace: str, resource_group: str) -> bool:
    rule_id   = rule.get("id") or str(uuid.uuid4())
    rule_name = rule.get("name", "Unknown")
    kind      = rule.get("kind", "Scheduled")

    print(f"\n  📤 Deployataan: {rule_name}")
    print(f"     ID: {rule_id}")

    properties = yaml_to_arm_properties(rule)

    body = {
        "kind": kind,
        "properties": properties
    }

    cmd = [
        "az", "rest",
        "--method", "PUT",
        "--url", (
            f"https://management.azure.com/subscriptions/{{subscriptionId}}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
            f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"
            f"?api-version=2023-12-01-preview"
        ),
        "--body", json.dumps(body),
        "--query", "{name:properties.displayName, severity:properties.severity, enabled:properties.enabled}"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            response = json.loads(result.stdout)
            print(f"     ✅ Onnistui! Severity: {response.get('severity')} | Enabled: {response.get('enabled')}")
            return True
        else:
            print(f"     ❌ Virhe:\n{result.stderr}")
            return False
    except Exception as e:
        print(f"     ❌ Poikkeus: {e}")
        return False


# ---------------------------------------------------------------------------
# Pääohjelma
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Deploy Sentinel Analytic Rules from YAML")
    parser.add_argument("--workspace",      required=True, help="Sentinel workspace nimi")
    parser.add_argument("--resource-group", required=True, help="Resource group nimi")
    parser.add_argument("--rules-path",     required=True, help="Kansio jossa YAML-säännöt")
    args = parser.parse_args()

    rules_path = Path(args.rules_path)
    if not rules_path.exists():
        print(f"❌ Kansiota ei löydy: {rules_path}")
        sys.exit(1)

    yaml_files = list(rules_path.rglob("*.yaml")) + list(rules_path.rglob("*.yml"))
    # Jätetään GitHub Actions workflow-tiedostot pois
    yaml_files = [f for f in yaml_files if ".github" not in str(f)]

    if not yaml_files:
        print(f"⚠️  Ei YAML-tiedostoja kansiossa: {rules_path}")
        sys.exit(0)

    print(f"\n🚀 Sentinel Rule Deployment")
    print(f"   Workspace:      {args.workspace}")
    print(f"   Resource Group: {args.resource_group}")
    print(f"   Säännöt:        {len(yaml_files)} kpl")
    print("─" * 50)

    ok = fail = 0
    for yaml_file in sorted(yaml_files):
        with open(yaml_file, encoding="utf-8") as f:
            rule = yaml.safe_load(f)

        if not rule or not isinstance(rule, dict):
            print(f"\n  ⚠️  Ohitetaan (tyhjä tai virheellinen): {yaml_file.name}")
            continue

        if deploy_rule(rule, args.workspace, args.resource_group):
            ok += 1
        else:
            fail += 1

    print("\n" + "─" * 50)
    print(f"✅ Onnistui: {ok}   ❌ Epäonnistui: {fail}")

    if fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()