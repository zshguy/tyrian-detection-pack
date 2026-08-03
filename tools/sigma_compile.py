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
import xml.etree.ElementTree as ET
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

# Linux rules in this pack read auditd. Wazuh's auditd decoder emits a flat
# `audit.*` namespace that looks nothing like the Windows one, and the Windows
# fallback further down would happily turn `Image` into `win.eventdata.image`
# for a Linux rule: a rule that compiles, deploys, and never fires. So the Linux
# maps are STRICT (an unmapped field raises) rather than falling back.
#
# Note there is deliberately no `CommandLine`. auditd does not have one: `comm`
# is just the process name and the real argv arrives split across EXECVE a0..aN.
# Mapping CommandLine onto `audit.command` would make `CommandLine|contains:
# '/dev/tcp/'` match the string "bash" and nothing else. Rules use ExecveA0..A4.
WAZUH_LINUX_FIELDS = {
    "Type": "audit.type",
    "Image": "audit.exe",
    "Comm": "audit.command",
    "ExecveA0": "audit.execve.a0",
    "ExecveA1": "audit.execve.a1",
    "ExecveA2": "audit.execve.a2",
    "ExecveA3": "audit.execve.a3",
    "ExecveA4": "audit.execve.a4",
    "TargetFilename": "audit.file.name",
    "TargetDirectory": "audit.directory.name",
    "Cwd": "audit.cwd",
    "Syscall": "audit.syscall",
    "AuditKey": "audit.key",
    "Success": "audit.success",
    "User": "audit.auid",
    "Auid": "audit.auid",
    "Uid": "audit.uid",
    "Euid": "audit.euid",
    "Gid": "audit.gid",
    "Pid": "audit.pid",
    "Ppid": "audit.ppid",
    "Exit": "audit.exit",
}

# Splunk's auditd fields come from the Splunk Add-on for Unix and Linux
# (sourcetype `auditd`). Without that add-on installed these searches parse but
# match nothing, which the generated header says out loud.
SPLUNK_LINUX_FIELDS = {
    "Type": "type",
    "Image": "exe",
    "Comm": "comm",
    "ExecveA0": "a0",
    "ExecveA1": "a1",
    "ExecveA2": "a2",
    "ExecveA3": "a3",
    "ExecveA4": "a4",
    "TargetFilename": "name",
    "TargetDirectory": "name",
    "Cwd": "cwd",
    "Syscall": "syscall",
    "AuditKey": "key",
    "Success": "success",
    "User": "auid",
    "Auid": "auid",
    "Uid": "uid",
    "Euid": "euid",
    "Gid": "gid",
    "Pid": "pid",
    "Ppid": "ppid",
    "Exit": "exit",
}

# Sigma logsource -> the table/index each backend reads.
WAZUH_GROUPS = {
    ("windows", "security"): "windows,windows_security,",
    ("windows", "sysmon"): "sysmon,",
    ("windows", "powershell"): "windows,powershell,",
    ("windows", "system"): "windows,windows_system,",
    ("linux", "auditd"): "linux,audit,",
    ("linux", None): "linux,",
}
WAZUH_IF_GROUP = {
    ("windows", "sysmon"): "sysmon_event1",
    ("windows", "security"): "windows_security",
    ("windows", "system"): "windows_system",
    ("windows", "powershell"): "windows",
    ("linux", "auditd"): "audit",
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
    ("linux", "auditd"): 'sourcetype="auditd"',
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


REQUIRED = ("title", "id", "description", "logsource", "detection", "level", "tags", "validation")


def validate(rule: dict) -> list[str]:
    errs = [f"missing `{k}`" for k in REQUIRED if k not in rule]
    if rule.get("level") not in LEVEL_TO_WAZUH:
        errs.append(f"level must be one of {sorted(LEVEL_TO_WAZUH)}")

    # A rule nobody can trigger is a rule nobody can trust. `fire` has to be a
    # command a reader can actually run; `atomic` points at the Atomic Red Team
    # technique folder for a maintained version of the same test.
    val = rule.get("validation")
    if val is not None:
        if not isinstance(val, dict):
            errs.append("`validation` must be a mapping with `atomic` and `fire`")
        else:
            if not str(val.get("fire", "")).strip():
                errs.append("`validation.fire` must say how to trigger the rule")
            atomic = str(val.get("atomic", "")).strip()
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", atomic):
                errs.append(f"`validation.atomic` should be an ATT&CK technique id, got {atomic!r}")
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

    # Resolve every field against every backend that has to render it, so a
    # missing mapping fails in CI rather than halfway through a compile.
    platform = platform_of(rule)
    for sel in names:
        block = det[sel]
        if not isinstance(block, (dict, list)):
            continue
        for field, _mods, _values in iter_field_matches(block):
            for backend in ("wazuh", "splunk"):
                try:
                    resolve_field(backend, platform, field)
                except Unsupported as e:
                    errs.append(str(e))
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


def platform_of(rule: dict) -> str:
    """Which field taxonomy a rule speaks. Drives field resolution per backend."""
    return "linux" if rule.get("logsource", {}).get("product") == "linux" else "windows"


# Windows falls back to a derived Sysmon field name because Sysmon's schema is
# open-ended and the derivation is correct for it. Linux has no such regular
# fallback, so an unmapped field is an error the author has to resolve.
STRICT_FIELDS = {
    ("wazuh", "linux"): WAZUH_LINUX_FIELDS,
    ("splunk", "linux"): SPLUNK_LINUX_FIELDS,
}


def resolve_field(backend: str, platform: str, field: str) -> str:
    strict = STRICT_FIELDS.get((backend, platform))
    if strict is not None:
        if field not in strict:
            raise Unsupported(
                f"field {field!r} has no {backend} mapping for {platform}; "
                f"add it to {backend.upper()}_{platform.upper()}_FIELDS or use one of "
                f"{sorted(strict)}"
            )
        return strict[field]
    if backend == "wazuh":
        return WAZUH_FIELDS.get(field, f"win.eventdata.{field[0].lower() + field[1:]}")
    if backend == "sentinel":
        return SENTINEL_FIELDS.get(field, field)
    return field


# A Wazuh rule is one flat conjunction of <field> tests, so it cannot express a
# disjunction directly. Rewriting the condition into disjunctive normal form and
# emitting one sibling rule per disjunct is the faithful translation. Without
# this, `a or b` collapsed into `a and b`: a rule that looks fine, deploys fine,
# and can never fire.
MAX_WAZUH_VARIANTS = 12


def _cross_and(groups: list[list[tuple[list[str], list[str]]]]) -> list[tuple[list[str], list[str]]]:
    out: list[tuple[list[str], list[str]]] = [([], [])]
    for group in groups:
        merged = []
        for pos_a, neg_a in out:
            for pos_b, neg_b in group:
                merged.append((pos_a + pos_b, neg_a + neg_b))
        out = merged
    return out


def dnf(node) -> list[tuple[list[str], list[str]]]:
    """Condition AST -> list of (positive selections, negated selections).

    Each returned pair is one alternative that, on its own, satisfies the rule.
    """
    kind = node[0]
    if kind == "sel":
        return [([node[1]], [])]
    if kind == "or":
        out = []
        for child in node[1:]:
            out.extend(dnf(child))
        return out
    if kind == "and":
        return _cross_and([dnf(c) for c in node[1:]])
    if kind == "not":
        inner = node[1]
        if inner[0] == "sel":
            return [([], [inner[1]])]
        if inner[0] == "not":  # double negation
            return dnf(inner[1])
        # De Morgan: push the negation inward so the result stays in DNF.
        if inner[0] == "and":
            out = []
            for child in inner[1:]:
                out.extend(dnf(("not", child)))
            return out
        if inner[0] == "or":
            return _cross_and([dnf(("not", c)) for c in inner[1:]])
    raise Unsupported(f"cannot normalise condition node {kind!r}")


def _validation_lines(rule: dict) -> list[str]:
    """How to trigger this rule, carried through into every compiled artifact so
    the answer travels with the rule instead of living only in the repo."""
    val = rule.get("validation") or {}
    if not isinstance(val, dict):
        return []
    out = []
    if val.get("atomic"):
        out.append(f"validate: Atomic Red Team {val['atomic']}")
    for line in str(val.get("fire", "")).strip().splitlines():
        if line.strip():
            out.append(f"  {line.strip()}")
    return out


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
def _comment_safe(text: str) -> str:
    """XML comments may not contain a double hyphen, and libxml2 rejects the whole
    file when they do. Rule titles and file paths are unlikely offenders, but a
    single stray `--` would take down every rule on the manager, so everything
    routed into a comment goes through here. Content that genuinely needs a `--`
    (validation commands) is emitted as <info> element text instead, where it is
    legal and survives verbatim."""
    prev = None
    while prev != text:
        prev = text
        text = text.replace("--", "- -")
    return text


def _wazuh_info(rule: dict) -> str | None:
    """Validation guidance as element text. Unlike a comment this can hold `--`,
    which nearly every real attack command contains."""
    val = rule.get("validation") or {}
    if not isinstance(val, dict):
        return None
    cmds = [ln.strip() for ln in str(val.get("fire", "")).strip().splitlines() if ln.strip()]
    if not (val.get("atomic") or cmds):
        return None
    head = f"Validate (Atomic Red Team {val['atomic']})" if val.get("atomic") else "Validate"
    return f"{head}: {' | '.join(cmds)}" if cmds else head


def render_wazuh(rules: list[dict]) -> str:
    out = [
        "<!--",
        "  Tyrian Detection Pack - Wazuh rules (GENERATED, do not edit by hand).",
        "  Source of truth: rules/**.yml",
        "  Regenerate:      python tools/sigma_compile.py (wazuh backend, see README.md)",
        "",
        "  Install:  copy into /var/ossec/etc/rules/local_rules.xml on the manager, then",
        "            /var/ossec/bin/wazuh-control restart",
        "  IDs use the 100000+ local range Wazuh reserves for you.",
        "  Tune thresholds to your environment before relying on these.",
        "",
        "  Each rule carries an <info> line naming the Atomic Red Team technique and a",
        "  command that triggers it, so you can prove the rule fires before trusting it.",
        "-->",
        "",
    ]
    rid = 100100
    for rule in rules:
        det = rule["detection"]
        names = [k for k in det if k != "condition"]
        tree = parse_condition(str(det["condition"]), names)

        # Wazuh evaluates one flat conjunction per rule, so an `or` becomes a set
        # of sibling rules (one per DNF disjunct) rather than one rule that
        # silently ANDs everything together.
        variants = dnf(tree)
        if len(variants) > MAX_WAZUH_VARIANTS:
            raise Unsupported(
                f"{rule['_path']}: condition expands to {len(variants)} Wazuh rules "
                f"(limit {MAX_WAZUH_VARIANTS}); split the rule instead"
            )

        key = logsource_key(rule)
        group = WAZUH_GROUPS.get(key, "windows,")
        if_group = WAZUH_IF_GROUP.get(key, "windows")
        level = LEVEL_TO_WAZUH[rule["level"]]
        techniques = [t.split(".", 1)[1].upper() for t in rule["tags"] if str(t).startswith("attack.t")]

        agg = rule_aggregation(rule)
        out.append("<!-- " + _comment_safe(f'{rule["title"]}  [{rule["_path"]}]'))
        out.append(f'     status: {rule.get("status", "experimental")}')
        if len(variants) > 1:
            out.append(f"     NOTE: the source condition is a disjunction, so it compiles to "
                       f"{len(variants)} sibling rules below (any one of them firing means a hit).")
        out.append("-->")
        info = _wazuh_info(rule)
        platform = platform_of(rule)

        for idx, (positives, negatives) in enumerate(variants, start=1):
            label = rule["title"] if len(variants) == 1 else f"{rule['title']} ({idx}/{len(variants)}: {', '.join(positives)})"
            out.append(f'<group name="{group}">')
            out.append(f'  <rule id="{rid}" level="{level}">')
            out.append(f"    <if_group>{if_group}</if_group>")
            for sel in dict.fromkeys(positives):  # dedupe, preserve order
                for field, mods, values in iter_field_matches(det[sel]):
                    wf = resolve_field("wazuh", platform, field)
                    parts = [to_regex(v, mods) for v in values]
                    if "all" in mods and len(parts) > 1:
                        # `|all` means every value must be present. Alternation
                        # would mean "any", so require PCRE2 and AND them with
                        # lookaheads. Wazuh's default osregex has no lookahead.
                        pattern = "".join(f"(?=.*{p})" for p in parts)
                        attr = ' type="pcre2"'
                    else:
                        pattern = "|".join(parts)
                        attr = ' type="pcre2"' if len(parts) > 1 else ""
                    out.append(f'    <field name="{wf}"{attr}>{sx.escape(pattern)}</field>')
            if agg:
                out.append(f"    <frequency>{agg['threshold']}</frequency>")
                out.append(f"    <timeframe>{_seconds(agg['timeframe'])}</timeframe>")
                if agg.get("by"):
                    by = agg["by"]
                    # `by host` is the pack's shorthand for "per agent", which Wazuh
                    # already scopes natively, so it is not a decoder field lookup.
                    same = by if by == "host" else resolve_field("wazuh", platform, by)
                    out.append(f"    <same_field>{same}</same_field>")
            out.append(f"    <description>{sx.escape(label)}</description>")
            if info:
                out.append(f'    <info type="text">{sx.escape(info)}</info>')
            out.append("    <mitre>")
            for t in techniques:
                out.append(f"      <id>{t}</id>")
            out.append("    </mitre>")
            if negatives:
                excl = ", ".join(dict.fromkeys(negatives))
                out.append("    <!-- " + _comment_safe(
                    f'tune: source rule also excludes [{excl}]; '
                    f'add <field negate="yes"> as needed') + " -->")
            out.append("    <options>no_full_log</options>")
            out.append("  </rule>")
            out.append("</group>")
            out.append("")
            rid += 1

    xml = "\n".join(out)
    # Wazuh loads this file with libxml2, which rejects the *entire* ruleset on a
    # single well-formedness error. That failure mode is silent from here, so the
    # check belongs in the compiler: parse what we are about to hand over.
    try:
        ET.fromstring(f"<root>{xml}</root>")
    except ET.ParseError as e:
        raise Unsupported(
            f"generated Wazuh XML is not well-formed ({e}). Wazuh would refuse to load "
            f"the whole file. This is a compiler bug, not a rule bug."
        ) from e
    return xml


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

        platform = platform_of(rule)

        def render(node) -> str:
            kind = node[0]
            if kind == "sel":
                block = det[node[1]]
                clauses = []
                for field, mods, values in iter_field_matches(block):
                    sf = resolve_field("splunk", platform, field)
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
            if by != "host":
                by = resolve_field("splunk", platform, by)
            distinct = (
                f"dc({resolve_field('splunk', platform, agg['field'])})"
                if agg["field"] else "count"
            )
            spl += (f" | bucket _time span={agg['timeframe']}"
                    f" | stats {distinct} as hits by _time,{by}"
                    f" | where hits {agg['op']} {agg['threshold']}")
        out.append(f"[Tyrian - {rule['title']}]")
        out.append(f"description = {rule['description'].strip().splitlines()[0]}")
        out.append(f"search = {spl}")
        if platform == "linux":
            out.append("# requires the Splunk Add-on for Unix and Linux for auditd field extraction")
        out.append(f"# severity: {rule['level']}   techniques: {','.join(techniques_of(rule))}   status: {rule.get('status', 'experimental')}")
        for line in _validation_lines(rule):
            out.append(f"# {line}")
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


def render_sentinel(rules: list[dict]) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Returns (files, skipped). Skipped rules are reported, never silently dropped."""
    files, skipped = [], []
    for rule in rules:
        # auditd reaches Sentinel as unparsed Syslog text unless the customer has
        # built a custom table and DCR for it. There is no field mapping that is
        # right for everyone, and `SyslogMessage contains "/usr/bin/nc"` is not
        # the same detection as `Image == "/usr/bin/nc"`. Skip and say so.
        if platform_of(rule) == "linux":
            skipped.append((rule["_path"], "auditd has no faithful Sentinel field mapping"))
            continue
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
            f"// techniques: {techs}   severity: {rule['level']}   status: {rule.get('status', 'experimental')}",
            *[f"// {line}" for line in _validation_lines(rule)],
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
    return files, skipped


# --------------------------------------------------------------------------
# Backend: ATT&CK Navigator layer
# --------------------------------------------------------------------------
def techniques_of(rule: dict) -> list[str]:
    return [t.split(".", 1)[1].upper() for t in rule.get("tags", []) if str(t).startswith("attack.t")]


def render_navigator(rules: list[dict]) -> str:
    """An ATT&CK Navigator layer you can drop straight onto the matrix.

    Scored by how many rules cover each technique, so a coverage review shows
    both what is covered and where the pack is one rule deep.
    """
    by_tech: dict[str, list[dict]] = {}
    for rule in rules:
        for tech in techniques_of(rule):
            by_tech.setdefault(tech, []).append(rule)

    entries = []
    for tech, hits in sorted(by_tech.items()):
        stable = sum(1 for r in hits if r.get("status") == "stable")
        comment = "\n".join(
            f"{r['title']} [{r.get('status', 'experimental')}, {r['level']}]" for r in hits
        )
        entries.append({
            "techniqueID": tech,
            "score": len(hits),
            "comment": comment + (f"\n\n{stable} of {len(hits)} validated on a live range."
                                  if stable else ""),
            "enabled": True,
            "metadata": [
                {"name": "rules", "value": str(len(hits))},
                {"name": "validated", "value": str(stable)},
            ],
            "showSubtechniques": True,
        })

    layer = {
        "name": "Tyrian Detection Pack",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"{len(rules)} open-source Sigma detections covering {len(by_tech)} techniques, "
            "compiled to Wazuh, Splunk and Sentinel. "
            "https://github.com/zshguy/tyrian-detection-pack"
        ),
        "filters": {"platforms": ["Windows", "Linux"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": entries,
        "gradient": {
            # White through Tyrian magenta: darker means more rules on the technique.
            "colors": ["#f7e9f1", "#d16aa6", "#8a1259"],
            "minValue": 0,
            "maxValue": max((len(v) for v in by_tech.values()), default=1),
        },
        "legendItems": [
            {"label": "1 rule", "color": "#f7e9f1"},
            {"label": "2 rules", "color": "#d16aa6"},
            {"label": "3+ rules", "color": "#8a1259"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#2b2340",
        "selectTechniquesAcrossTactics": True,
        "metadata": [
            {"name": "source", "value": "https://github.com/zshguy/tyrian-detection-pack"},
            {"name": "license", "value": "MIT"},
        ],
    }
    return json.dumps(layer, indent=2)


# --------------------------------------------------------------------------
# Backend: COVERAGE.md
# --------------------------------------------------------------------------
TACTIC_TITLES = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}
# ATT&CK's own kill-chain order, so the doc reads like the matrix rather than
# like a directory listing.
TACTIC_ORDER = list(TACTIC_TITLES)


def render_coverage(rules: list[dict]) -> str:
    techs = sorted({t for r in rules for t in techniques_of(r)})
    stable = sum(1 for r in rules if r.get("status") == "stable")
    platforms = sorted({platform_of(r) for r in rules})

    out = [
        "# Coverage",
        "",
        "GENERATED by `python tools/sigma_compile.py --backend coverage`. Do not edit by hand.",
        "",
        f"**{len(rules)} rules** covering **{len(techs)} ATT&CK techniques** across "
        f"**{len({r['_tactic'] for r in rules})} tactics** on {' and '.join(platforms)}.",
        "",
        f"{stable} rules are marked `stable`, meaning the detection was tuned against telemetry",
        f"from a live detonation. The remaining {len(rules) - stable} are `experimental`: the logic is",
        "sound and the fields are real, but they have not been fired on a range yet. Every rule",
        "carries a `validation:` note telling you how to trigger it yourself.",
        "",
        "| Backend | Rules emitted |",
        "|---|---:|",
        f"| Wazuh | {len(rules)} |",
        f"| Splunk | {len(rules)} |",
    ]
    sentinel_n = sum(1 for r in rules if platform_of(r) != "linux")
    out.append(
        f"| Sentinel | {sentinel_n} |" if sentinel_n == len(rules)
        else f"| Sentinel | {sentinel_n} ({len(rules) - sentinel_n} Linux auditd rules have no "
             f"faithful KQL mapping) |"
    )
    out.append("")

    by_tactic: dict[str, list[dict]] = {}
    for rule in rules:
        by_tactic.setdefault(rule["_tactic"], []).append(rule)

    ordered = [t for t in TACTIC_ORDER if t in by_tactic]
    ordered += [t for t in sorted(by_tactic) if t not in TACTIC_TITLES]

    for tactic in ordered:
        rows = sorted(by_tactic[tactic], key=lambda r: r["title"])
        out.append(f"## {TACTIC_TITLES.get(tactic, tactic)} ({len(rows)})")
        out.append("")
        out.append("| Rule | Technique | Level | Status | Platform |")
        out.append("|---|---|---|---|---|")
        for r in rows:
            tech = ", ".join(techniques_of(r))
            ls = r.get("logsource", {})
            plat = f"{ls.get('product', '?')}/{ls.get('service', '-')}"
            out.append(
                f"| [{r['title']}]({r['_path']}) | {tech} | {r['level']} | "
                f"{r.get('status', 'experimental')} | {plat} |"
            )
        out.append("")

    out += [
        "## Technique index",
        "",
        ", ".join(f"`{t}`" for t in techs),
        "",
        "Drop [`dist/navigator/tyrian-detection-pack.json`](dist/navigator/tyrian-detection-pack.json)",
        "into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to see this",
        "as a heat map.",
        "",
    ]
    return "\n".join(out)


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Compile Tyrian Sigma rules to SIEM dialects.")
    ap.add_argument(
        "--backend",
        choices=["wazuh", "splunk", "sentinel", "navigator", "coverage", "validate", "stats"],
        required=True,
    )
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
    elif args.backend == "navigator":
        _emit(render_navigator(rules), args.out, "tyrian-detection-pack.json")
    elif args.backend == "coverage":
        text = render_coverage(rules)
        if args.out:
            _emit(text, args.out, "COVERAGE.md")
        else:
            (ROOT / "COVERAGE.md").write_text(text, encoding="utf-8")
            print(f"wrote {ROOT / 'COVERAGE.md'}", file=sys.stderr)
    else:
        files, skipped = render_sentinel(rules)
        for path, why in skipped:
            print(f"skipped (sentinel): {path}: {why}", file=sys.stderr)
        if not args.out:
            for _, body in files:
                print(body)
        else:
            d = pathlib.Path(args.out)
            d.mkdir(parents=True, exist_ok=True)
            for name, body in files:
                (d / name).write_text(body, encoding="utf-8")
            if skipped:
                (d / "_NOT_TRANSLATED.md").write_text(
                    "# Rules with no Sentinel output\n\n"
                    "These compile for Wazuh and Splunk but are deliberately not emitted as\n"
                    "KQL, because auditd arrives in Sentinel as unparsed `Syslog` text unless\n"
                    "you have built a custom table and DCR for it. A substring match on\n"
                    "`SyslogMessage` is not the same detection as a field match, so the\n"
                    "compiler declines rather than shipping something subtly weaker.\n\n"
                    + "".join(f"- `{p}` ({why})\n" for p, why in skipped),
                    encoding="utf-8",
                )
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
