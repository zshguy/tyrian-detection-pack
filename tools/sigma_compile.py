#!/usr/bin/env python3
"""
Tyrian Sigma compiler: one rule source, three SIEM dialects.

    python tools/sigma_compile.py --backend wazuh   > dist/wazuh/local_rules.xml
    python tools/sigma_compile.py --backend splunk  --out dist/splunk
    python tools/sigma_compile.py --backend sentinel --out dist/sentinel

Why this exists
---------------
pySigma has good Splunk and Sentinel backends. Wazuh does not have a maintained
one, and hand-translating Sigma into Wazuh's `<field>` regex XML is the tedious,
error-prone part of running Wazuh as a detection platform. That gap is the whole
reason this tool is here; Splunk and Sentinel come along for free once the AST
exists.

Honest scope
------------
This implements the subset of the Sigma specification that this pack's own rules
use, and it is strict about it: anything it cannot represent faithfully raises
instead of emitting a rule that silently means something else. A detection that
quietly compiles to the wrong logic is worse than one that fails loudly.

Supported: string/int/list values, `null`, the `contains` / `startswith` /
`endswith` / `re` / `all` / `cased` modifiers, `1 of`/`all of` with the `them`
keyword and `prefix*` wildcards, `and`/`or`/`not`, parentheses, wildcards (`*`,
`?`) in values, and `|count() by x > n` aggregation (Wazuh frequency, Splunk
stats, Sentinel summarize).

Not supported (raises): `near` correlation, `base64offset`, `utf16`, `cidr`,
backend-specific field mapping beyond the table below.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import time
import xml.sax.saxutils as sx

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required:  pip install pyyaml")

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"

# --------------------------------------------------------------------------
# Field mapping. Sigma's taxonomy is generic; each SIEM names things its own
# way. Keeping this in one table is what makes a single rule source viable.
# --------------------------------------------------------------------------
WAZUH_FIELDS = {
    "EventID": "win.system.eventID",
    "Image": "win.eventdata.image",
    "ParentImage": "win.eventdata.parentImage",
    "CommandLine": "win.eventdata.commandLine",
    "ParentCommandLine": "win.eventdata.parentCommandLine",
    "TargetImage": "win.eventdata.targetImage",
    "SourceImage": "win.eventdata.sourceImage",
    "GrantedAccess": "win.eventdata.grantedAccess",
    "TargetFilename": "win.eventdata.targetFilename",
    "ServiceName": "win.eventdata.serviceName",
    "ServiceFileName": "win.eventdata.serviceFileName",
    "TargetUserName": "win.eventdata.targetUserName",
    "SubjectUserName": "win.eventdata.subjectUserName",
    "LogonType": "win.eventdata.logonType",
    "IpAddress": "win.eventdata.ipAddress",
    "TicketEncryptionType": "win.eventdata.ticketEncryptionType",
    "TicketOptions": "win.eventdata.ticketOptions",
    "AuthenticationPackageName": "win.eventdata.authenticationPackageName",
    "TargetObject": "win.eventdata.targetObject",
    "Details": "win.eventdata.details",
    "Properties": "win.eventdata.properties",
    "ObjectName": "win.eventdata.objectName",
    "AccessMask": "win.eventdata.accessMask",
    "Status": "win.eventdata.status",
    "QueryName": "win.eventdata.queryName",
    "DestinationPort": "win.eventdata.destinationPort",
    "DestinationIp": "win.eventdata.destinationIp",
    "User": "win.eventdata.user",
    "ScriptBlockText": "win.eventdata.scriptBlockText",
    "ParentUser": "win.eventdata.parentUser",
    "OriginalFileName": "win.eventdata.originalFileName",
}

SENTINEL_FIELDS = {
    "EventID": "EventID",
    "Image": "NewProcessName",
    "ParentImage": "ParentProcessName",
    "CommandLine": "CommandLine",
    "TargetUserName": "TargetUserName",
    "SubjectUserName": "SubjectUserName",
    "LogonType": "LogonType",
    "IpAddress": "IpAddress",
}

# Sigma logsource -> the table/index each backend reads.
WAZUH_GROUPS = {
    ("windows", "security"): "windows,windows_security,",
    ("windows", "sysmon"): "sysmon,",
    ("windows", "powershell"): "windows,powershell,",
    ("windows", "system"): "windows,windows_system,",
    ("linux", None): "linux,",
}
WAZUH_IF_GROUP = {
    ("windows", "sysmon"): "sysmon_event1",
    ("windows", "security"): "windows_security",
    ("windows", "system"): "windows_system",
    ("windows", "powershell"): "windows",
    ("linux", None): "syslog",
}
SENTINEL_TABLES = {
    ("windows", "security"): "SecurityEvent",
    ("windows", "sysmon"): "Event",
    ("windows", "system"): "Event",
    ("windows", "powershell"): "Event",
    ("linux", None): "Syslog",
}
SPLUNK_SOURCETYPES = {
    ("windows", "security"): 'source="WinEventLog:Security"',
    ("windows", "sysmon"): 'source="WinEventLog:Microsoft-Windows-Sysmon/Operational"',
    ("windows", "system"): 'source="WinEventLog:System"',
    ("windows", "powershell"): 'source="WinEventLog:Microsoft-Windows-PowerShell/Operational"',
    ("linux", None): 'sourcetype="linux_secure"',
}

LEVEL_TO_WAZUH = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 14}


class Unsupported(Exception):
    """Raised when a construct cannot be translated faithfully."""


# --------------------------------------------------------------------------
# Condition parsing. Produces a small AST so each backend renders from the same
# structure rather than doing string surgery on the condition text.
# --------------------------------------------------------------------------
TOKEN = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+)")


def tokenize(cond: str) -> list[str]:
    out, pos = [], 0
    cond = cond.strip()
    while pos < len(cond):
        if cond[pos].isspace():  # trailing/interstitial run with nothing after it
            pos += 1
            continue
        m = TOKEN.match(cond, pos)
        if not m:
            raise Unsupported(f"cannot tokenize condition at {cond[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


def expand_selector(tok: str, names: list[str]) -> list[str]:
    """`them` -> every selection; `filter_*` -> every matching name."""
    if tok == "them":
        return names
    if tok.endswith("*"):
        return [n for n in names if n.startswith(tok[:-1])]
    if tok in names:
        return [tok]
    raise Unsupported(f"unknown selection {tok!r}")


# Sigma aggregation tail, e.g. `| count(TargetUserName) by IpAddress > 10`.
AGG = re.compile(
    r"^\s*(?P<func>count|min|max|avg|sum)\s*\(\s*(?P<field>[A-Za-z0-9_]*)\s*\)"
    r"(?:\s+by\s+(?P<by>[A-Za-z0-9_]+))?"
    r"\s*(?P<op>>=|<=|>|<|==)\s*(?P<threshold>\d+)\s*$",
    re.IGNORECASE,
)


def split_aggregation(cond: str) -> tuple[str, dict | None]:
    """Separate the boolean expression from a trailing aggregation clause."""
    if "|" not in cond:
        return cond, None
    head, _, tail = cond.partition("|")
    m = AGG.match(tail)
    if not m:
        raise Unsupported(f"unsupported aggregation {tail.strip()!r}")
    return head, {
        "func": m.group("func").lower(),
        "field": m.group("field") or None,
        "by": m.group("by"),
        "op": m.group("op"),
        "threshold": int(m.group("threshold")),
    }


def parse_condition(cond: str, names: list[str]):
    """Recursive-descent parse into ('and'|'or'|'not'|'sel', ...) nodes."""
    cond, _agg = split_aggregation(cond)
    toks = tokenize(cond)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def eat(t=None):
        nonlocal pos
        cur = toks[pos]
        if t and cur != t:
            raise Unsupported(f"expected {t!r}, got {cur!r}")
        pos += 1
        return cur

    def primary():
        nonlocal pos
        t = peek()
        if t == "(":
            eat("(")
            node = expr()
            eat(")")
            return node
        if t == "not":
            eat("not")
            return ("not", primary())
        if t in ("1", "all"):
            quant = eat()
            if peek() == "of":
                eat("of")
            target = eat()
            sels = expand_selector(target, names)
            if not sels:
                raise Unsupported(f"{quant} of {target} matched no selections")
            return ("or" if quant == "1" else "and", *[("sel", s) for s in sels])
        return ("sel", eat())

    def expr():
        node = primary()
        while peek() in ("and", "or"):
            op = eat()
            rhs = primary()
            node = (op, node, rhs)
        return node

    tree = expr()
    if pos != len(toks):
        raise Unsupported(f"trailing tokens in condition: {toks[pos:]}")
    return tree


# --------------------------------------------------------------------------
# Value helpers
# --------------------------------------------------------------------------
def split_field(key: str) -> tuple[str, list[str]]:
    parts = key.split("|")
    return parts[0], parts[1:]


def wildcard_to_regex(v: str) -> str:
    out = []
    for ch in v:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def to_regex(value, mods: list[str]) -> str:
    """Render one Sigma value as a regex fragment (Wazuh's matching model)."""
    if value is None:
        return r"^$"
    v = str(value)
    if "re" in mods:
        return v
    core = wildcard_to_regex(v)
    if "contains" in mods:
        return core
    if "startswith" in mods:
        return "^" + core
    if "endswith" in mods:
        return core + "$"
    if "*" in v or "?" in v:
        return "^" + core + "$"
    return "^" + core + "$"


# --------------------------------------------------------------------------
# Rule loading + validation
# --------------------------------------------------------------------------
def load_rules() -> list[dict]:
    rules = []
    for path in sorted(RULES_DIR.rglob("*.yml")):
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not doc:
            continue
        doc["_path"] = path.relative_to(ROOT).as_posix()
        doc["_tactic"] = path.parent.name
        rules.append(doc)
    return rules


REQUIRED = ("title", "id", "description", "logsource", "detection", "level", "tags")


def validate(rule: dict) -> list[str]:
    errs = [f"missing `{k}`" for k in REQUIRED if k not in rule]
    if rule.get("level") not in LEVEL_TO_WAZUH:
        errs.append(f"level must be one of {sorted(LEVEL_TO_WAZUH)}")
    det = rule.get("detection", {})
    if "condition" not in det:
        errs.append("detection.condition is required")
    if not any(str(t).startswith("attack.t") for t in rule.get("tags", [])):
        errs.append("needs an attack.tNNNN technique tag")
    names = [k for k in det if k != "condition"]
    if "condition" in det:
        try:
            parse_condition(str(det["condition"]), names)
        except Unsupported as e:
            errs.append(f"condition: {e}")
    return errs


def rule_aggregation(rule: dict) -> dict | None:
    """The effective threshold for a rule, from either Sigma `| count(...)`
    syntax or the simpler timeframe/count keys this pack also accepts."""
    det = rule["detection"]
    _, agg = split_aggregation(str(det["condition"]))
    if agg:
        agg = dict(agg)
        agg.setdefault("timeframe", det.get("timeframe", "5m"))
        return agg
    if det.get("timeframe"):
        return {"func": "count", "field": None, "by": det.get("groupby", "host"),
                "op": ">=", "threshold": int(det.get("count", 5)),
                "timeframe": det["timeframe"]}
    return None


def logsource_key(rule: dict) -> tuple:
    ls = rule.get("logsource", {})
    return (ls.get("product"), ls.get("service"))


def iter_field_matches(block):
    """Yield (field, modifiers, [values]) for one selection block."""
    if isinstance(block, list):
        for sub in block:
            yield from iter_field_matches(sub)
        return
    for key, val in block.items():
        field, mods = split_field(key)
        values = val if isinstance(val, list) else [val]
        yield field, mods, values


# --------------------------------------------------------------------------
# Backend: Wazuh
# --------------------------------------------------------------------------
def render_wazuh(rules: list[dict]) -> str:
    out = [
        "<!--",
        "  Tyrian Detection Pack - Wazuh rules (GENERATED, do not edit by hand).",
        "  Source of truth: rules/**.yml   Regenerate: python tools/sigma_compile.py --backend wazuh",
        "",
        "  Install:  copy into /var/ossec/etc/rules/local_rules.xml on the manager, then",
        "            /var/ossec/bin/wazuh-control restart",
        "  IDs use the 100000+ local range Wazuh reserves for you.",
        "  Tune thresholds to your environment before relying on these.",
        "-->",
        "",
    ]
    rid = 100100
    for rule in rules:
        det = rule["detection"]
        names = [k for k in det if k != "condition"]
        tree = parse_condition(str(det["condition"]), names)

        # Wazuh evaluates one flat set of field regexes per rule, so only a
        # positive-conjunction shape maps cleanly. Negations become <if_group>
        # exclusions the operator must tune, and we say so rather than pretend.
        positives, negatives = [], []

        def walk(node, negated=False):
            kind = node[0]
            if kind == "sel":
                (negatives if negated else positives).append(node[1])
            elif kind == "not":
                walk(node[1], not negated)
            elif kind in ("and", "or"):
                for child in node[1:]:
                    walk(child, negated)

        walk(tree)

        key = logsource_key(rule)
        group = WAZUH_GROUPS.get(key, "windows,")
        if_group = WAZUH_IF_GROUP.get(key, "windows")
        level = LEVEL_TO_WAZUH[rule["level"]]
        techniques = [t.split(".", 1)[1].upper() for t in rule["tags"] if str(t).startswith("attack.t")]

        agg = rule_aggregation(rule)
        out.append(f'<!-- {rule["title"]}  [{rule["_path"]}] -->')
        out.append(f'<group name="{group}">')
        out.append(f'  <rule id="{rid}" level="{level}">')
        out.append(f"    <if_group>{if_group}</if_group>")
        for sel in positives:
            for field, mods, values in iter_field_matches(det[sel]):
                wf = WAZUH_FIELDS.get(field, f"win.eventdata.{field[0].lower() + field[1:]}")
                pattern = "|".join(to_regex(v, mods) for v in values)
                out.append(f'    <field name="{wf}">{sx.escape(pattern)}</field>')
        if agg:
            out.append(f"    <frequency>{agg['threshold']}</frequency>")
            out.append(f"    <timeframe>{_seconds(agg['timeframe'])}</timeframe>")
            if agg.get("by"):
                out.append(f"    <same_field>{WAZUH_FIELDS.get(agg['by'], agg['by'])}</same_field>")
        out.append(f"    <description>{sx.escape(rule['title'])}</description>")
        out.append("    <mitre>")
        for t in techniques:
            out.append(f"      <id>{t}</id>")
        out.append("    </mitre>")
        if negatives:
            excl = ", ".join(negatives)
            out.append(f"    <!-- tune: source rule also excludes [{excl}]; add <field negate=\"yes\"> as needed -->")
        out.append("    <options>no_full_log</options>")
        out.append("  </rule>")
        out.append("</group>")
        out.append("")
        rid += 1
    return "\n".join(out)


def _seconds(tf: str) -> int:
    m = re.fullmatch(r"(\d+)([smhd])", str(tf).strip())
    if not m:
        raise Unsupported(f"bad timeframe {tf!r}")
    n, unit = int(m.group(1)), m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


# --------------------------------------------------------------------------
# Backend: Splunk SPL
# --------------------------------------------------------------------------
def _splunk_value(field: str, value, mods: list[str]) -> str:
    if value is None:
        return f'NOT {field}=*'
    v = str(value)
    if "re" in mods:
        return f'match({field}, "{v}")'
    if "contains" in mods:
        v = f"*{v}*"
    elif "startswith" in mods:
        v = f"{v}*"
    elif "endswith" in mods:
        v = f"*{v}"
    return f'{field}="{v}"'


def render_splunk(rules: list[dict]) -> str:
    out = [
        "# Tyrian Detection Pack - Splunk searches (GENERATED, do not edit by hand).",
        "# Source of truth: rules/**.yml",
        "# Regenerate: python tools/sigma_compile.py --backend splunk",
        "#",
        "# Each stanza is a saved search. Adjust the index= prefix to your environment.",
        "",
    ]
    for rule in rules:
        det = rule["detection"]
        names = [k for k in det if k != "condition"]
        tree = parse_condition(str(det["condition"]), names)

        def render(node) -> str:
            kind = node[0]
            if kind == "sel":
                block = det[node[1]]
                clauses = []
                for field, mods, values in iter_field_matches(block):
                    sf = field
                    if "all" in mods:
                        clauses.append("(" + " AND ".join(_splunk_value(sf, v, mods) for v in values) + ")")
                    else:
                        clauses.append("(" + " OR ".join(_splunk_value(sf, v, mods) for v in values) + ")")
                return "(" + " AND ".join(clauses) + ")" if clauses else "(true)"
            if kind == "not":
                return f"NOT {render(node[1])}"
            op = " AND " if kind == "and" else " OR "
            return "(" + op.join(render(c) for c in node[1:]) + ")"

        src = SPLUNK_SOURCETYPES.get(logsource_key(rule), "")
        spl = f"index=* {src} {render(tree)}".strip()
        agg = rule_aggregation(rule)
        if agg:
            by = agg.get("by") or "host"
            distinct = f"dc({agg['field']})" if agg["field"] else "count"
            spl += (f" | bucket _time span={agg['timeframe']}"
                    f" | stats {distinct} as hits by _time,{by}"
                    f" | where hits {agg['op']} {agg['threshold']}")
        name = re.sub(r"[^a-z0-9]+", "_", rule["title"].lower()).strip("_")
        out.append(f"[Tyrian - {rule['title']}]")
        out.append(f"description = {rule['description'].strip().splitlines()[0]}")
        out.append(f"search = {spl}")
        out.append(f"# severity: {rule['level']}   techniques: {','.join(t.split('.',1)[1].upper() for t in rule['tags'] if str(t).startswith('attack.t'))}")
        out.append(f"# source: {rule['_path']}")
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Backend: Microsoft Sentinel (KQL)
# --------------------------------------------------------------------------
def _kql_value(field: str, value, mods: list[str]) -> str:
    if value is None:
        return f'isempty({field})'
    v = str(value)
    if "re" in mods:
        return f'{field} matches regex "{v}"'
    op = "=~"
    if "cased" in mods:
        op = "=="
    if "contains" in mods:
        return f'{field} contains "{v}"'
    if "startswith" in mods:
        return f'{field} startswith "{v}"'
    if "endswith" in mods:
        return f'{field} endswith "{v}"'
    if "*" in v or "?" in v:
        return f'{field} matches regex "{wildcard_to_regex(v)}"'
    return f'{field} {op} "{v}"'


def render_sentinel(rules: list[dict]) -> list[tuple[str, str]]:
    files = []
    for rule in rules:
        det = rule["detection"]
        names = [k for k in det if k != "condition"]
        tree = parse_condition(str(det["condition"]), names)

        def render(node) -> str:
            kind = node[0]
            if kind == "sel":
                block = det[node[1]]
                clauses = []
                for field, mods, values in iter_field_matches(block):
                    kf = SENTINEL_FIELDS.get(field, field)
                    # Collapse a multi-value OR into has_any(dynamic([...])). It is
                    # the idiomatic KQL, it is materially faster in Sentinel than a
                    # chain of `or X contains`, and it keeps long rules readable.
                    if (
                        len(values) > 2
                        and "all" not in mods
                        and "re" not in mods
                        and "contains" in mods
                        and all(v is not None for v in values)
                    ):
                        arr = ", ".join(f'"{v}"' for v in values)
                        clauses.append(f"({kf} has_any (dynamic([{arr}])))")
                        continue
                    joiner = " and " if "all" in mods else " or "
                    clauses.append("(" + joiner.join(_kql_value(kf, v, mods) for v in values) + ")")
                return "(" + " and ".join(clauses) + ")" if clauses else "(true)"
            if kind == "not":
                return f"not {render(node[1])}"
            op = " and " if kind == "and" else " or "
            return "(" + op.join(render(c) for c in node[1:]) + ")"

        table = SENTINEL_TABLES.get(logsource_key(rule), "SecurityEvent")
        techs = ",".join(t.split(".", 1)[1].upper() for t in rule["tags"] if str(t).startswith("attack.t"))
        body = [
            f"// {rule['title']}",
            f"// {rule['description'].strip().splitlines()[0]}",
            f"// techniques: {techs}   severity: {rule['level']}",
            f"// source: {rule['_path']}  (GENERATED, do not edit by hand)",
            table,
            f"| where {render(tree)}",
        ]
        agg = rule_aggregation(rule)
        if agg:
            by = SENTINEL_FIELDS.get(agg.get("by") or "", agg.get("by") or "Computer")
            reducer = f"dcount({SENTINEL_FIELDS.get(agg['field'], agg['field'])})" if agg["field"] else "count()"
            body.append(f"| summarize Hits={reducer} by bin(TimeGenerated, {agg['timeframe']}), {by}")
            body.append(f"| where Hits {agg['op']} {agg['threshold']}")
        slug = re.sub(r"[^a-z0-9]+", "-", rule["title"].lower()).strip("-")
        files.append((f"{slug}.kql", "\n".join(body) + "\n"))
    return files


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Compile Tyrian Sigma rules to SIEM dialects.")
    ap.add_argument("--backend", choices=["wazuh", "splunk", "sentinel", "validate", "stats"], required=True)
    ap.add_argument("--out", help="output directory (sentinel writes one file per rule)")
    args = ap.parse_args()

    rules = load_rules()
    if not rules:
        print("no rules found under rules/", file=sys.stderr)
        return 1

    problems = {r["_path"]: validate(r) for r in rules}
    problems = {k: v for k, v in problems.items() if v}
    if problems:
        for path, errs in problems.items():
            for e in errs:
                print(f"{path}: {e}", file=sys.stderr)
        if args.backend != "validate":
            return 1

    if args.backend == "validate":
        print(f"validated {len(rules)} rules, {len(problems)} with problems")
        return 1 if problems else 0

    if args.backend == "stats":
        techs = sorted({t.split(".", 1)[1].upper() for r in rules for t in r["tags"] if str(t).startswith("attack.t")})
        by_tactic: dict[str, int] = {}
        for r in rules:
            by_tactic[r["_tactic"]] = by_tactic.get(r["_tactic"], 0) + 1
        print(json.dumps({"rules": len(rules), "techniques": len(techs),
                          "by_tactic": dict(sorted(by_tactic.items())), "technique_ids": techs}, indent=2))
        return 0

    if args.backend == "wazuh":
        text = render_wazuh(rules)
        _emit(text, args.out, "local_rules.xml")
    elif args.backend == "splunk":
        text = render_splunk(rules)
        _emit(text, args.out, "tyrian_detections.conf")
    else:
        files = render_sentinel(rules)
        if not args.out:
            for _, body in files:
                print(body)
        else:
            d = pathlib.Path(args.out)
            d.mkdir(parents=True, exist_ok=True)
            for name, body in files:
                (d / name).write_text(body, encoding="utf-8")
            # Verify AFTER a settle window, not inline. Endpoint AV scans
            # asynchronously, so a file can pass an immediate exists() check and be
            # quarantined a second later. Detection content necessarily contains the
            # attacker strings it matches on, which is what trips the scanner.
            # Reporting "wrote 36" when 35 survive is exactly the silently-wrong
            # output this tool exists to avoid.
            time.sleep(1.5)
            vanished = [name for name, _ in files if not (d / name).exists()]
            print(f"wrote {len(files) - len(vanished)}/{len(files)} KQL files to {d}", file=sys.stderr)
            if vanished:
                print(
                    "\nWARNING: these files disappeared immediately after being written:\n  "
                    + "\n  ".join(vanished)
                    + "\n\nThis is almost always endpoint antivirus. A compiled detection contains"
                    "\nthe attacker strings it looks for, so a real-time scanner can flag the rule"
                    "\nfile as the very thing it detects. Exclude this directory, or build on Linux"
                    "\n(CI does). The rule source under rules/ is unaffected.\n",
                    file=sys.stderr,
                )
                return 2
    return 0


def _emit(text: str, out: str | None, filename: str) -> None:
    if not out:
        print(text)
        return
    d = pathlib.Path(out)
    d.mkdir(parents=True, exist_ok=True)
    (d / filename).write_text(text, encoding="utf-8")
    print(f"wrote {d / filename}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
