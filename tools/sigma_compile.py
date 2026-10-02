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
`endswith` / `re` (with `i`/`m`/`s` flags) / `all` / `cased` / `windash` /
`cidr` / `base64` / `base64offset` (with `utf16le`/`utf16be`/`utf16`/`wide`)
modifiers, `1 of`/`all of` with the `them` keyword and `prefix*` wildcards,
`and`/`or`/`not`, parentheses, wildcards (`*`, `?`) in values, and
`|count() by x > n` aggregation (Wazuh frequency, Splunk stats, Sentinel
summarize).

Not supported (raises): `near` correlation, `fieldref`, `exists`, numeric
comparison modifiers, and any modifier not listed above. Wazuh additionally
refuses IPv6 and non-octet-aligned IPv4 `cidr` values rather than widening them.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import time
import xml.etree.ElementTree as ET
import xml.sax.saxutils as sx
import base64
import ipaddress
import itertools

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
    # auditd names its own fields in lower case, and Sigma rules written against
    # auditd use those names directly rather than the Sigma-style ones above.
    # They are the same fields, so they are listed rather than refused. Lookup is
    # case-insensitive on top of this, which covers `type` against `Type`.
    "exe": "audit.exe",
    "key": "audit.key",
    "name": "audit.file.name",
    "dir": "audit.directory.name",
    "a0": "audit.execve.a0",
    "a1": "audit.execve.a1",
    "a2": "audit.execve.a2",
    "a3": "audit.execve.a3",
    "a4": "audit.execve.a4",
    "a5": "audit.execve.a5",
    "ExecveA5": "audit.execve.a5",
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
    # As above: the names auditd itself uses, which is how Sigma auditd rules
    # are written.
    "exe": "exe",
    "key": "key",
    "name": "name",
    "dir": "name",
    "a0": "a0",
    "a1": "a1",
    "a2": "a2",
    "a3": "a3",
    "a4": "a4",
    "a5": "a5",
    "ExecveA5": "a5",
}

# Cloud audit feeds. Each backend ingests these through its own connector, and
# each connector names the same JSON differently, so every product gets a table
# per backend plus a derivation for the long tail of fields (CloudTrail's
# requestParameters.* alone is open-ended). Falling through to the Windows
# derivation instead would turn `eventName` into `win.eventdata.eventName`: a
# rule that deploys cleanly and can never fire.
CLOUD_PRODUCTS = ("aws", "azure", "m365")

# Sentinel's AWSCloudTrail table flattens userIdentity.* into columns and keeps
# the request/response bodies as dynamic JSON.
SENTINEL_AWS_FIELDS = {
    "eventName": "EventName",
    "eventSource": "EventSource",
    "eventType": "EventTypeName",
    "errorCode": "ErrorCode",
    "errorMessage": "ErrorMessage",
    "sourceIPAddress": "SourceIpAddress",
    "userAgent": "UserAgent",
    "awsRegion": "AWSRegion",
    "recipientAccountId": "RecipientAccountId",
    "userIdentity.type": "UserIdentityType",
    "userIdentity.arn": "UserIdentityArn",
    "userIdentity.userName": "UserIdentityUserName",
    "userIdentity.accountId": "UserIdentityAccountId",
    "userIdentity.principalId": "UserIdentityPrincipalid",
}
SENTINEL_AWS_DYNAMIC = {
    "requestParameters": "RequestParameters",
    "responseElements": "ResponseElements",
    "additionalEventData": "AdditionalEventData",
}

# Entra ID via the Splunk Add-on for Microsoft Cloud Services (Event Hub,
# sourcetype azure:monitor:aad). Azure Monitor's diagnostic envelope keeps a few
# fields top level and the rest under `properties`.
SPLUNK_AZURE_FIELDS = {
    "ResultType": "resultType",
    "OperationName": "operationName",
    "Category": "category",
    "IPAddress": "callerIpAddress",
    "UserPrincipalName": "properties.userPrincipalName",
    "AppDisplayName": "properties.appDisplayName",
    "TargetResources": "properties.targetResources{}.modifiedProperties{}.newValue",
}

# OfficeActivity / the O365 management API keep `Parameters` as an array of
# {Name, Value}. Sentinel stores it as a string, and so does Wazuh's decoder,
# which substring matching handles. Splunk extracts it as two multivalue fields,
# so a substring test that should see both names and values goes to _raw.
SPLUNK_M365_FIELDS = {"Parameters": "_raw"}


def _cloud_field(backend: str, platform: str, field: str) -> str:
    if platform == "aws":
        if backend == "wazuh":
            return f"aws.{field}"  # Wazuh's aws-s3 wodle decodes CloudTrail JSON under aws.
        if backend == "sentinel":
            if field in SENTINEL_AWS_FIELDS:
                return SENTINEL_AWS_FIELDS[field]
            head, _, rest = field.partition(".")
            if head in SENTINEL_AWS_DYNAMIC and rest:
                return f"tostring(parse_json({SENTINEL_AWS_DYNAMIC[head]}).{rest})"
            return "".join(part[:1].upper() + part[1:] for part in field.split("."))
        return field  # Splunk aws:cloudtrail keeps the JSON paths as-is.
    if platform == "m365":
        if backend == "wazuh":
            return f"office365.{field}"
        if backend == "splunk":
            return SPLUNK_M365_FIELDS.get(field, field)
        return field  # OfficeActivity uses the management API names.
    # azure (Entra ID sign-in and audit logs)
    if backend == "splunk":
        return SPLUNK_AZURE_FIELDS.get(field, "properties." + field[:1].lower() + field[1:])
    if backend == "sentinel" and field == "TargetResources":
        return "tostring(TargetResources)"
    # Sentinel columns carry the Log Analytics names, and Wazuh's azure-logs
    # module forwards Log Analytics rows as flat JSON under those same names.
    return field


# Sigma logsource -> the table/index each backend reads.
WAZUH_GROUPS = {
    ("windows", "security"): "windows,windows_security,",
    ("windows", "sysmon"): "sysmon,",
    ("windows", "powershell"): "windows,powershell,",
    ("windows", "system"): "windows,windows_system,",
    ("linux", "auditd"): "linux,audit,",
    ("linux", None): "linux,",
    # Product-level fallback. A rule that gives `product: windows` and a
    # category but no service (Sigma writes most process_creation rules that
    # way) is still a Windows rule, and dropping it to "unknown" would strip
    # scoping from the majority of any real corpus.
    ("windows", None): "windows,",
    ("aws", None): "amazon,aws,",
    ("azure", None): "azure,",
    ("m365", None): "office365,",
}
WAZUH_IF_GROUP = {
    ("windows", "sysmon"): "sysmon_event1",
    ("windows", "security"): "windows_security",
    ("windows", "system"): "windows_system",
    ("windows", "powershell"): "windows",
    ("linux", "auditd"): "audit",
    ("linux", None): "syslog",
    ("windows", None): "windows",
    ("aws", None): "amazon",
    ("azure", None): "azure",
    ("m365", None): "office365",
}
SENTINEL_TABLES = {
    ("windows", "security"): "SecurityEvent",
    ("windows", "sysmon"): "Event",
    ("windows", "system"): "Event",
    ("windows", "powershell"): "Event",
    ("linux", None): "Syslog",
    ("aws", None): "AWSCloudTrail",
    ("azure", "signinlogs"): "SigninLogs",
    ("azure", "auditlogs"): "AuditLogs",
    ("azure", "activitylogs"): "AzureActivity",
    ("m365", None): "OfficeActivity",
}
SPLUNK_SOURCETYPES = {
    ("windows", "security"): 'source="WinEventLog:Security"',
    ("windows", "sysmon"): 'source="WinEventLog:Microsoft-Windows-Sysmon/Operational"',
    ("windows", "system"): 'source="WinEventLog:System"',
    ("windows", "powershell"): 'source="WinEventLog:Microsoft-Windows-PowerShell/Operational"',
    ("linux", "auditd"): 'sourcetype="auditd"',
    ("linux", None): 'sourcetype="linux_secure"',
    ("aws", None): 'sourcetype="aws:cloudtrail"',
    ("azure", None): 'sourcetype="azure:monitor:aad"',
    ("m365", None): 'sourcetype="o365:management:activity"',
}

LEVEL_TO_WAZUH = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 14}


class Unsupported(Exception):
    """Raised when a construct cannot be translated faithfully."""


# Set from --source-url / --source-license when compiling somebody elses corpus.
# Redistributing converted rules is explicitly allowed by the Detection Rule
# License that SigmaHQ uses, provided the author travels with the rule, a link
# back is included where practicable, and the license is named. All three are
# emitted into the compiled output rather than living only in a README, because
# the compiled file is the thing that gets copied onto a manager.
ATTRIBUTION = {"url_template": None, "license": None, "corpus": None}


def source_link(rule: dict) -> "str | None":
    """Link back to the original rule, if a --source-url template was given."""
    template = ATTRIBUTION.get("url_template")
    if not template:
        return None
    return template.replace("{path}", rule.get("_relpath") or rule.get("_path", ""))


def attribution_header() -> list:
    """Lines naming where the rules came from and under what terms."""
    if not (ATTRIBUTION.get("corpus") or ATTRIBUTION.get("license")):
        return []
    out = [""]
    if ATTRIBUTION.get("license"):
        out.append(f"  The rules remain the work of their original authors, under {ATTRIBUTION['license']}.")
        out.append("  Each rule below carries its author and a link back to the original.")
    return out


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


# Sigma string escaping (spec + pySigma): `*` and `?` are wildcards, and a
# backslash escapes a following `*`, `?` or `\\`. Any other backslash is a
# literal. So `'\\\\lsass.exe'` and `'\\lsass.exe'` both mean one backslash.
# Treating every character literally made `\\\\powershell.exe` demand TWO
# backslashes in the event: a rule that deploys cleanly and never fires.
WILD_MANY, WILD_ONE = object(), object()


def sigma_tokens(v: str) -> list:
    """Split a Sigma value into literal characters and wildcard markers."""
    out, i = [], 0
    while i < len(v):
        ch = v[i]
        if ch == "\\" and i + 1 < len(v) and v[i + 1] in "*?\\":
            out.append(v[i + 1])
            i += 2
            continue
        out.append(WILD_MANY if ch == "*" else WILD_ONE if ch == "?" else ch)
        i += 1
    return out


def has_wildcard(v: str) -> bool:
    return any(t is WILD_MANY or t is WILD_ONE for t in sigma_tokens(v))


def sigma_literal(v: str) -> str:
    """The value with escapes resolved. Only meaningful when it has no wildcards."""
    return "".join(t for t in sigma_tokens(v) if isinstance(t, str))


def wildcard_to_regex(v: str) -> str:
    out = []
    for t in sigma_tokens(v):
        if t is WILD_MANY:
            out.append(".*")
        elif t is WILD_ONE:
            out.append(".")
        else:
            out.append(re.escape(t))
    return "".join(out)


# Every modifier the compiler understands. Anything else raises: `fieldref`,
# `exists`, `gt`/`lt` and friends have no faithful rendering on these backends,
# and silently dropping a modifier is the worst outcome of all. `|cidr:
# 10.0.0.0/8` rendered as a literal is a rule that deploys and never matches.
MODS_MATCH = {"contains", "startswith", "endswith", "all", "cased", "re", "windash", "cidr"}
MODS_ENCODE = {"base64", "base64offset", "utf16le", "utf16be", "utf16", "wide"}
MODS_RE_FLAGS = {"i", "m", "s"}
KNOWN_MODS = MODS_MATCH | MODS_ENCODE | MODS_RE_FLAGS

# pySigma's base64offset: three encodings, one per alignment of the plaintext
# inside the surrounding base64 stream, each trimmed of the boundary characters
# that depend on the unknown neighbours.
_B64_START = (0, 2, 3)
_B64_END = (None, -3, -2)

# The dash variants `windash` stands for, as pySigma enumerates them.
WINDASH = ["-", "/", "\u2013", "\u2014", "\u2015"]


def expand_values(values: list, mods: list[str]) -> tuple[list, list[str]]:
    """Apply the encoding modifiers, which turn one value into one or more
    literal strings, and strip them from the modifier list. Also the place an
    unknown modifier is refused, before any backend renders it."""
    unknown = [m for m in mods if m not in KNOWN_MODS]
    if unknown:
        raise Unsupported(f"unsupported modifier{'s' if len(unknown) > 1 else ''} "
                          f"{'|'.join(unknown)!r} (known: {', '.join(sorted(KNOWN_MODS))})")
    if "re" in mods and (set(mods) & (MODS_MATCH - {"re"})):
        raise Unsupported("`re` cannot be combined with other matching modifiers")
    if "cidr" in mods and (set(mods) & (MODS_MATCH - {"cidr"})):
        raise Unsupported("`cidr` cannot be combined with other matching modifiers")
    enc = [m for m in mods if m in MODS_ENCODE]
    if not enc:
        return values, mods
    if "re" in mods or "cidr" in mods or "windash" in mods:
        raise Unsupported("base64/utf16 modifiers cannot be combined with re, cidr or windash")
    codec = "utf-8"
    bom = b""
    for m in enc:
        if m in ("utf16le", "wide"):
            codec = "utf-16le"
        elif m == "utf16be":
            codec = "utf-16be"
        elif m == "utf16":
            codec, bom = "utf-16le", b"\xff\xfe"
    out = []
    for v in values:
        if v is None:
            raise Unsupported("null cannot be base64 encoded")
        raw = bom + sigma_literal(str(v)).encode(codec)
        if "base64offset" in enc:
            for i in range(3):
                enc_b = base64.b64encode(b" " * i + raw).decode("ascii")
                out.append(enc_b[_B64_START[i]:_B64_END[(len(raw) + i) % 3]])
        elif "base64" in enc:
            out.append(base64.b64encode(raw).decode("ascii"))
        else:
            raise Unsupported("utf16 modifiers only make sense before base64 or base64offset")
    # base64 is case-sensitive; matching it case-insensitively would widen the
    # rule to strings that decode to something else.
    rest = [m for m in mods if m not in MODS_ENCODE]
    if "cased" not in rest:
        rest.append("cased")
    return out, rest


def _cidr(value) -> "ipaddress.IPv4Network | ipaddress.IPv6Network":
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except ValueError as e:
        raise Unsupported(f"cidr value {value!r} is not a network: {e}") from e


def cidr_regex(value) -> str:
    """A CIDR as an anchored regex, for backends with no network primitive.
    Only octet-aligned IPv4 prefixes (and /32) have a faithful regex; anything
    else is refused rather than approximated with a wider prefix."""
    net = _cidr(value)
    if net.version != 4:
        raise Unsupported(f"cidr {value!r}: IPv6 has no faithful regex rendering on this backend")
    if net.prefixlen % 8:
        raise Unsupported(f"cidr {value!r}: only /8, /16, /24 and /32 can be rendered as a regex "
                          f"on this backend without widening the match")
    octets = str(net.network_address).split(".")[: net.prefixlen // 8]
    tail = "" if net.prefixlen == 32 else r"\."
    return "^" + r"\.".join(re.escape(o) for o in octets) + tail


def windash_regex(core: str) -> str:
    """Replace each escaped dash in a regex fragment with the windash class."""
    # re.escape renders `-` as `\-`, so that is the only spelling to replace.
    return core.replace(r"\-", "[" + "".join(WINDASH) + "]")


def to_regex(value, mods: list[str], unfielded: bool = False) -> str:
    """Render one Sigma value as a regex fragment (Wazuh's matching model).

    `unfielded` is Sigma keyword search, where the value has to appear somewhere
    in the event rather than be the whole of a named field. That is substring
    matching, so the anchors a field test needs would be wrong: `^PermissionDenied$`
    against a whole log line is a rule that deploys cleanly and never fires."""
    if value is None:
        return r"^$"
    v = str(value)
    if "re" in mods:
        flags = "".join(f for f in MODS_RE_FLAGS if f in mods)
        return f"(?{flags})" + v if flags else v
    if "cidr" in mods:
        return cidr_regex(v)
    core = wildcard_to_regex(v)
    if "windash" in mods:
        core = windash_regex(core)
    if "contains" in mods:
        return core
    if "startswith" in mods:
        return "^" + core
    if "endswith" in mods:
        return core + "$"
    if unfielded:
        return core
    return "^" + core + "$"


# --------------------------------------------------------------------------
# Rule loading + validation
# --------------------------------------------------------------------------
def _display_path(path: pathlib.Path) -> str:
    """Shortest path that still identifies the file to whoever reads the error.

    Relative to the pack for bundled rules, relative to the working directory
    for a corpus somebody pointed us at, absolute as a last resort."""
    resolved = path.resolve()
    for base in (ROOT, pathlib.Path.cwd()):
        try:
            return resolved.relative_to(base).as_posix()
        except ValueError:
            continue
    return resolved.as_posix()


def tactic_of(doc: dict, path: pathlib.Path) -> str:
    """Which ATT&CK tactic a rule belongs to.

    This pack encodes it in the directory name. A foreign corpus does not,
    because SigmaHQ organises by log source rather than by tactic, so fall back
    to the `attack.<tactic>` tag and normalise the underscores Sigma uses into
    the hyphenated spelling used everywhere else here."""
    if path.parent.name in TACTIC_TITLES:
        return path.parent.name
    for tag in doc.get("tags") or []:
        name = str(tag).lower()
        if name.startswith("attack."):
            name = name.split(".", 1)[1].replace("_", "-")
            if name in TACTIC_TITLES:
                return name
    return "uncategorised"


def load_rules(inputs=None) -> list[dict]:
    """Load every Sigma document under the given paths, defaulting to this pack.

    Any Sigma tree works, which is most of the reason the compiler is worth
    having on its own: pointing it at a SigmaHQ checkout is the common case.

    A file that cannot be parsed is carried through as an entry with
    `_unreadable` set rather than dropped, because a corpus report that quietly
    omits the files it choked on is exactly the kind of soft lie this tool
    exists to avoid."""
    roots = [pathlib.Path(i) for i in (inputs or [RULES_DIR])]
    rules: list[dict] = []
    seen: set = set()
    for root in roots:
        if root.is_file():
            paths = [root]
        else:
            paths = sorted(set(root.rglob("*.yml")) | set(root.rglob("*.yaml")))
        for path in paths:
            key = path.resolve()
            if key in seen:
                continue
            seen.add(key)
            shown = _display_path(path)
            try:
                # safe_load_all, not safe_load: Sigma permits a multi-document
                # file (a shared `action: global` head plus per-rule bodies),
                # and safe_load raises on the second document rather than
                # reading it.
                with open(path, "r", encoding="utf-8") as fh:
                    docs = list(yaml.safe_load_all(fh))
            except OSError as e:
                # Not a YAML problem, and saying so matters: on Windows this is
                # almost always the 260-character path limit biting a deep
                # SigmaHQ checkout, which has a fix the reader can act on.
                hint = ""
                if os.name == "nt" and len(str(path.resolve())) > 255:
                    hint = (" (path is over 260 characters; enable long paths with "
                            "`git config --system core.longpaths true` or check out "
                            "nearer the drive root)")
                rules.append({"_path": shown, "_tactic": "uncategorised",
                              "_unreadable": f"could not read file: {e.strerror or e}{hint}"})
                continue
            except (yaml.YAMLError, UnicodeDecodeError) as e:
                detail = str(e).splitlines()[0] if str(e).strip() else type(e).__name__
                rules.append({"_path": shown, "_tactic": "uncategorised",
                              "_unreadable": f"unparseable YAML: {detail}"})
                continue
            for doc in docs:
                # Skip collection heads, index files and anything else that is
                # not a rule. A Sigma rule is the thing with a `detection`.
                if not isinstance(doc, dict) or "detection" not in doc:
                    continue
                doc["_path"] = shown
                # Relative to the corpus root, so a --source-url template can
                # build a link back to the original rule. Attribution under the
                # Detection Rule License wants a URI to the specific rule where
                # that is practicable, and this is what makes it practicable.
                try:
                    doc["_relpath"] = path.resolve().relative_to(root.resolve()).as_posix()
                except ValueError:
                    doc["_relpath"] = path.name
                doc["_tactic"] = tactic_of(doc, path)
                rules.append(doc)
    return rules


REQUIRED = ("title", "id", "description", "logsource", "detection", "level", "tags", "validation")


# What a rule needs before it can be translated at all, as opposed to what it
# needs in order to ship *in* this pack. That difference is the whole of --lax.
MINIMUM = ("title", "logsource", "detection")


def relax(rule: dict) -> list[str]:
    """Fill in what a foreign corpus is allowed to omit, and report what was filled.

    An evidence block on every rule, and a level drawn from a fixed set, are
    house standards here. Neither is a translation-fidelity question, so a rule
    from somebody else gets a default and a note rather than a refusal."""
    notes = []
    if rule.get("level") not in LEVEL_TO_WAZUH:
        had = f"level {rule['level']!r}" if "level" in rule else "no level"
        notes.append(f"{had}; treated as medium")
        rule["level"] = "medium"
    if not any(str(t).startswith("attack.t") for t in rule.get("tags") or []):
        rule.setdefault("tags", [])
        notes.append("no attack.tNNNN tag; emitted without a technique mapping")
    rule.setdefault("description", rule.get("title", ""))
    rule.setdefault("id", "")
    return notes


def validate(rule: dict, strict: bool = True) -> list[str]:
    """Problems that would stop this rule compiling faithfully.

    `strict` additionally enforces the house standards every rule in this pack
    has to meet. Lax mode keeps only the checks that decide whether the output
    would be *correct*, which is what you want when the corpus is not yours."""
    errs = [f"missing `{k}`" for k in (REQUIRED if strict else MINIMUM) if k not in rule]
    if strict and rule.get("level") not in LEVEL_TO_WAZUH:
        errs.append(f"level must be one of {sorted(LEVEL_TO_WAZUH)}")

    # A rule nobody can trigger is a rule nobody can trust. `fire` has to be a
    # command a reader can actually run; `atomic` points at the Atomic Red Team
    # technique folder for a maintained version of the same test.
    val = rule.get("validation")
    if strict and val is not None:
        if not isinstance(val, dict):
            errs.append("`validation` must be a mapping with `atomic` and `fire`")
        else:
            if not str(val.get("fire", "")).strip():
                errs.append("`validation.fire` must say how to trigger the rule")
            atomic = str(val.get("atomic", "")).strip()
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", atomic):
                errs.append(f"`validation.atomic` should be an ATT&CK technique id, got {atomic!r}")
    det = rule.get("detection", {})
    if not isinstance(det, dict):
        return errs + ["`detection` must be a mapping"]
    if "condition" not in det:
        errs.append("detection.condition is required")
    if strict and not any(str(t).startswith("attack.t") for t in rule.get("tags", [])):
        errs.append("needs an attack.tNNNN technique tag")
    names = selection_names(det)
    if "condition" in det:
        cond = det["condition"]
        # Sigma allows a list of conditions, meaning "any of these". This
        # compiler renders one condition per rule, so say that plainly instead
        # of stringifying the list into something that parses but means
        # nothing like the original.
        if isinstance(cond, list):
            errs.append("condition is a list (implicit OR of conditions); "
                        "split it into one rule per condition")
        else:
            try:
                parse_condition(str(cond), names)
            except Unsupported as e:
                errs.append(f"condition: {e}")

    # Resolve every field against every backend that has to render it, so a
    # missing mapping fails in CI rather than halfway through a compile. In lax
    # mode the renderer itself is the oracle instead, once per requested
    # backend, so a rule is never refused over a backend nobody asked for.
    if not strict:
        return errs
    platform = platform_of(rule)
    for sel in names:
        block = det[sel]
        if not isinstance(block, (dict, list)):
            continue
        for field, mods, values in iter_field_matches(block):
            try:
                expand_values(values, mods)
            except Unsupported as e:
                errs.append(f"{field or 'keywords'}: {e}")
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
    product = rule.get("logsource", {}).get("product")
    if product == "linux" or product in CLOUD_PRODUCTS:
        return product
    return "windows"


# Windows falls back to a derived Sysmon field name because Sysmon's schema is
# open-ended and the derivation is correct for it. Linux has no such regular
# fallback, so an unmapped field is an error the author has to resolve.
STRICT_FIELDS = {
    ("wazuh", "linux"): WAZUH_LINUX_FIELDS,
    ("splunk", "linux"): SPLUNK_LINUX_FIELDS,
}


# Fields that only exist in a process-creation feed. On Windows they are ordinary
# Sysmon fields. On Linux they mean the rule was written against Sysmon for Linux
# or auditbeat rather than auditd, and silently mapping them to an auditd field
# would produce a rule that deploys cleanly and can never match.
PROCESS_FEED_FIELDS = {
    "CommandLine", "ParentCommandLine", "ParentImage", "ParentProcessId",
    "ParentProcessGuid", "ProcessGuid", "CurrentDirectory", "IntegrityLevel",
    "LogonId", "LogonGuid", "OriginalFileName", "Company", "Product",
    "Description", "Hashes", "DestinationHostname", "DestinationIp",
    "DestinationPort", "SourceIp", "SourcePort", "Initiated", "Protocol",
}

_FOLDED_FIELD_CACHE: dict = {}


def _folded_fields(backend: str, platform: str, table: dict) -> dict:
    """Case-insensitive view of a strict field table, built once per table."""
    key = (backend, platform)
    if key not in _FOLDED_FIELD_CACHE:
        folded: dict = {}
        for name, mapped in table.items():
            folded.setdefault(name.lower(), mapped)
        _FOLDED_FIELD_CACHE[key] = folded
    return _FOLDED_FIELD_CACHE[key]


def resolve_field(backend: str, platform: str, field: str) -> str:
    # The empty field is Sigma unfielded keyword search, which by definition has
    # no field to resolve. Each renderer decides how to say "anywhere in the
    # event", or declines.
    if not field:
        return ""
    strict = STRICT_FIELDS.get((backend, platform))
    if strict is not None:
        if field in strict:
            return strict[field]
        # Same field, different capitalisation, is not worth refusing a rule
        # over. Sigma auditd rules say `type`; the table says `Type`.
        folded = _folded_fields(backend, platform, strict)
        if field.lower() in folded:
            return folded[field.lower()]
        if field in PROCESS_FEED_FIELDS:
            raise Unsupported(
                f"field {field!r} is not an auditd field. Linux rules compile against the "
                f"Wazuh auditd decoder, where a process argv arrives split across EXECVE "
                f"a0..aN and no single command line exists. A rule using {field!r} with "
                f"logsource.product linux is written for a process-creation agent "
                f"(Sysmon for Linux, auditbeat), which this compiler does not map, so "
                f"translating it would produce a rule that deploys and never matches"
            )
        raise Unsupported(
            f"field {field!r} has no {backend} mapping for {platform}; "
            f"add it to {backend.upper()}_{platform.upper()}_FIELDS or use one of "
            f"{sorted(strict)}"
        )
    if platform in CLOUD_PRODUCTS:
        return _cloud_field(backend, platform, field)
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


# Keys that live under `detection:` without being selections. `1 of them` and
# `all of them` expand over selection names, and a keyword scan walks selection
# blocks, so counting `timeframe` among them silently turns a threshold into a
# search term.
DETECTION_META = {"condition", "timeframe", "count", "groupby"}


def selection_names(det: dict) -> list:
    """The selection names in a detection block, in source order."""
    return [k for k in det if k not in DETECTION_META]


def selection_blocks(det: dict) -> list:
    """The selection bodies in a detection block."""
    return [b for k, b in det.items() if k not in DETECTION_META]


def iter_field_matches(block):
    """Yield (field, modifiers, [values]) for one selection block.

    A field of "" is Sigma unfielded keyword search: the value has to appear
    somewhere in the event rather than in a named field. It is written either as
    a bare list of strings under a selection name, or as a `|all` key with no
    field in front of the pipe. Backends that can express that faithfully render
    it; the ones that cannot decline the rule."""
    if not isinstance(block, (dict, list)):
        yield "", [], [block]
        return
    if isinstance(block, list):
        # A list of scalars is a keyword list, meaning any of these. A list of
        # maps is a list of selections, which is an OR the caller handles.
        scalars = [b for b in block if not isinstance(b, (dict, list))]
        if scalars:
            yield "", [], scalars
        for sub in block:
            if isinstance(sub, (dict, list)):
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


def _wazuh_author(rule: dict) -> str | None:
    """Rule author, carried onto the manager so attribution survives the
    conversion. The Detection Rule License asks that alerts based on a rule keep
    identifying its author, so this belongs in the rule, not in a README."""
    author = rule.get("author")
    if isinstance(author, list):
        author = ", ".join(str(a) for a in author)
    author = str(author or "").strip()
    return f"Rule by {author}" if author else None


def render_wazuh(rules: list[dict]) -> str:
    # When compiling somebody elses corpus the header must not imply the rules
    # are ours. Provenance in a generated artifact is not a courtesy, it is the
    # only thing telling whoever finds this file on a manager where it came from.
    if ATTRIBUTION.get("corpus"):
        provenance = [
            f"  Wazuh rules compiled from {ATTRIBUTION['corpus']}",
            "  by the Tyrian Detection Pack compiler (GENERATED, do not edit by hand).",
            "  https://github.com/zshguy/tyrian-detection-pack",
        ]
    else:
        provenance = [
            "  Tyrian Detection Pack - Wazuh rules (GENERATED, do not edit by hand).",
            "  Source of truth: rules/**.yml",
            "  Regenerate:      python tools/sigma_compile.py (wazuh backend, see README.md)",
        ]
    out = ["<!--"] + provenance + [
        "",
        "  Install:  copy into /var/ossec/etc/rules/local_rules.xml on the manager, then",
        "            /var/ossec/bin/wazuh-control restart",
        "  IDs use the 100000+ local range Wazuh reserves for you.",
        "  Tune thresholds to your environment before relying on these.",
    ] + attribution_header() + [
        "-->",
        "",
    ]
    rid = 100100
    for rule in rules:
        det = rule["detection"]
        names = selection_names(det)
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
        # An unmapped logsource used to fall back to the Windows group, which
        # quietly scoped a Django or macOS rule to Windows events and guaranteed
        # it would never fire. Emitting no <if_group> is the honest translation:
        # unscoped, evaluated against everything, and flagged for tuning.
        product_key = (key[0], None)
        known_logsource = key in WAZUH_GROUPS or product_key in WAZUH_GROUPS
        group = WAZUH_GROUPS.get(key) or WAZUH_GROUPS.get(product_key, "sigma,")
        if_group = WAZUH_IF_GROUP.get(key) or WAZUH_IF_GROUP.get(product_key)
        level = LEVEL_TO_WAZUH[rule["level"]]
        techniques = [t.split(".", 1)[1].upper() for t in rule["tags"] if str(t).startswith("attack.t")]

        agg = rule_aggregation(rule)
        shown_path = rule.get("_relpath") if ATTRIBUTION.get("corpus") else None
        out.append("<!-- " + _comment_safe(f'{rule["title"]}  [{shown_path or rule["_path"]}]'))
        out.append(f'     status: {rule.get("status", "experimental")}')
        if not known_logsource:
            ls = rule.get("logsource", {}) or {}
            out.append(_comment_safe(
                f'     TUNE: logsource product={ls.get("product")!r} service={ls.get("service")!r} '
                f'category={ls.get("category")!r} has no Wazuh group mapping, so this rule carries no '
                f'<if_group> and is evaluated against every decoded event. Scope it before you deploy it.'))
        if len(variants) > 1:
            out.append(f"     NOTE: the source condition is a disjunction, so it compiles to "
                       f"{len(variants)} sibling rules below (any one of them firing means a hit).")
        out.append("-->")
        info = _wazuh_info(rule)
        credit = _wazuh_author(rule)
        link = source_link(rule)
        platform = platform_of(rule)

        for idx, (positives, negatives) in enumerate(variants, start=1):
            label = rule["title"] if len(variants) == 1 else f"{rule['title']} ({idx}/{len(variants)}: {', '.join(positives)})"
            out.append(f'<group name="{group}">')
            out.append(f'  <rule id="{rid}" level="{level}">')
            if if_group:
                out.append(f"    <if_group>{if_group}</if_group>")
            for sel in dict.fromkeys(positives):  # dedupe, preserve order
                for field, mods, values in iter_field_matches(det[sel]):
                    wf = resolve_field("wazuh", platform, field)
                    values, mods = expand_values(values, mods)
                    parts = [to_regex(v, mods, unfielded=not wf) for v in values]
                    if "all" in mods and len(parts) > 1:
                        # `|all` means every value must be present. Alternation
                        # would mean "any", so AND them with lookaheads.
                        pattern = "".join(f"(?=.*{p})" for p in parts)
                    else:
                        pattern = "|".join(parts)
                    # Always PCRE2: the patterns are Python-style regex, which
                    # Wazuh's default osregex does not speak (there `\.` means
                    # "any character"). And Sigma matching is case-insensitive
                    # unless |cased, or |re which is case-sensitive by spec, so
                    # `-EncodedCommand` must also catch `-encodedcommand`.
                    if "cased" not in mods and "re" not in mods:
                        pattern = "(?i)" + pattern
                    attr = ' type="pcre2"'
                    if wf:
                        out.append(f'    <field name="{wf}"{attr}>{sx.escape(pattern)}</field>')
                    else:
                        # Unfielded keyword. Wazuh <regex> tests the whole
                        # decoded log, which is exactly what Sigma means here.
                        out.append(f'    <regex{attr}>{sx.escape(pattern)}</regex>')
            if agg:
                out.append(f"    <frequency>{agg['threshold']}</frequency>")
                out.append(f"    <timeframe>{_seconds(agg['timeframe'])}</timeframe>")
                if agg.get("by"):
                    by = agg["by"]
                    # `by host` is the pack's shorthand for "per agent", which Wazuh
                    # already scopes natively, so it is not a decoder field lookup.
                    same = by if by == "host" else resolve_field("wazuh", platform, by)
                    out.append(f"    <same_field>{same}</same_field>")
                if agg.get("field"):
                    # count(field) means distinct values. Without this Wazuh
                    # counts events, so ten failures against ONE account would
                    # pass for a spray across ten.
                    out.append(f"    <different_field>{resolve_field('wazuh', platform, agg['field'])}</different_field>")
            out.append(f"    <description>{sx.escape(label)}</description>")
            if credit:
                out.append(f'    <info type="text">{sx.escape(credit)}</info>')
            if info:
                out.append(f'    <info type="text">{sx.escape(info)}</info>')
            if link:
                out.append(f'    <info type="link">{sx.escape(link)}</info>')
            if techniques:
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
    # An empty field is Sigma unfielded keyword search. In SPL that is a bare
    # term, which is matched against the raw event rather than a named field.
    if value is None:
        return f'NOT {field}=*' if field else "NOT _raw=*"
    v = str(value)
    if "re" in mods:
        flags = "".join(f for f in MODS_RE_FLAGS if f in mods)
        rx = (f"(?{flags})" if flags else "") + v
        rx = rx.replace("\\", "\\\\").replace('"', '\\"')
        return f'match({field or "_raw"}, "{rx}")'
    if "cidr" in mods:
        # SPL matches CIDR natively on fields with IP values, both families.
        return f'{field}="{_cidr(v).with_prefixlen}"'
    if "windash" in mods:
        # No character class in an SPL wildcard, so enumerate the variants the
        # way pySigma does. Bounded, because a value with many dashes would
        # otherwise explode into thousands of terms.
        dashes = v.count("-")
        if dashes > 3:
            raise Unsupported(f"windash on a value with {dashes} dashes expands to "
                              f"{len(WINDASH) ** dashes} SPL terms; split the rule")
        base = [m for m in mods if m != "windash"]
        parts = v.split("-")
        alts = []
        for combo in itertools.product(WINDASH, repeat=dashes):
            joined = parts[0] + "".join(d + p for d, p in zip(combo, parts[1:]))
            alts.append(_splunk_value(field, joined, base))
        return "(" + " OR ".join(alts) + ")"
    # Resolve Sigma escapes, then escape for an SPL quoted string. SPL has no
    # single-character wildcard, so `?` widens to `*` rather than matching a
    # literal question mark that is almost never there.
    v = "".join(
        "*" if t is WILD_MANY or t is WILD_ONE else t.replace("\\", "\\\\").replace('"', '\\"')
        for t in sigma_tokens(v)
    )
    if "contains" in mods:
        v = f"*{v}*"
    elif "startswith" in mods:
        v = f"{v}*"
    elif "endswith" in mods:
        v = f"*{v}"
    elif not field:
        # Sigma keyword semantics are "appears in the event", so substring,
        # not the token equality a bare unquoted SPL term would give.
        v = f"*{v}*"
    return f'{field}="{v}"' if field else f'"{v}"'


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
        names = selection_names(det)
        tree = parse_condition(str(det["condition"]), names)

        platform = platform_of(rule)

        def render(node) -> str:
            kind = node[0]
            if kind == "sel":
                block = det[node[1]]
                clauses = []
                for field, mods, values in iter_field_matches(block):
                    sf = resolve_field("splunk", platform, field)
                    values, mods = expand_values(values, mods)
                    if "all" in mods:
                        clauses.append("(" + " AND ".join(_splunk_value(sf, v, mods) for v in values) + ")")
                    else:
                        clauses.append("(" + " OR ".join(_splunk_value(sf, v, mods) for v in values) + ")")
                return "(" + " AND ".join(clauses) + ")" if clauses else "(true)"
            if kind == "not":
                return f"NOT {render(node[1])}"
            op = " AND " if kind == "and" else " OR "
            return "(" + op.join(render(c) for c in node[1:]) + ")"

        key = logsource_key(rule)
        src = SPLUNK_SOURCETYPES.get(key) or SPLUNK_SOURCETYPES.get((key[0], None), "")
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
def _kql_str(s: str) -> str:
    """A KQL verbatim string literal. Backslashes are everywhere in Windows
    detections, and in a regular KQL string `"\\lsass.exe"` is a syntax error."""
    return '@"' + s.replace('"', '""') + '"'


def _kql_value(field: str, value, mods: list[str]) -> str:
    if value is None:
        return f'isempty({field})'
    # EventID and friends are int columns; `=~ "22"` does not compare an int.
    if isinstance(value, int) and not isinstance(value, bool) and not mods:
        return f'{field} == {value}'
    v = str(value)
    if "re" in mods:
        flags = "".join(f for f in MODS_RE_FLAGS if f in mods)
        return f'{field} matches regex {_kql_str((f"(?{flags})" if flags else "") + v)}'
    if "cidr" in mods:
        net = _cidr(v)
        fn = "ipv4_is_in_range" if net.version == 4 else "ipv6_is_in_range"
        return f'{fn}({field}, {_kql_str(net.with_prefixlen)})'
    if has_wildcard(v) or ("windash" in mods and "-" in v):
        # contains/startswith/endswith take literals in KQL, so an embedded
        # wildcard has to become an (anchored as appropriate) regex.
        core = wildcard_to_regex(v)
        if "windash" in mods:
            core = windash_regex(core)
        head = "" if ("contains" in mods or "endswith" in mods) else "^"
        tail = "" if ("contains" in mods or "startswith" in mods) else "$"
        flag = "" if "cased" in mods else "(?i)"
        return f'{field} matches regex {_kql_str(flag + head + core + tail)}'
    lit = _kql_str(sigma_literal(v))
    cs = "_cs" if "cased" in mods else ""
    if "contains" in mods:
        return f'{field} contains{cs} {lit}'
    if "startswith" in mods:
        return f'{field} startswith{cs} {lit}'
    if "endswith" in mods:
        return f'{field} endswith{cs} {lit}'
    return f'{field} {"==" if cs else "=~"} {lit}'


def render_sentinel(rules: list[dict]) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Returns (files, skipped). Skipped rules are reported, never silently dropped."""
    files, skipped = [], []
    for rule in rules:
        # auditd reaches Sentinel as unparsed Syslog text unless the customer has
        # built a custom table and DCR for it. There is no field mapping that is
        # right for everyone, and `SyslogMessage contains "/usr/bin/nc"` is not
        # the same detection as `Image == "/usr/bin/nc"`. Skip and say so.
        platform = platform_of(rule)
        if platform == "linux":
            skipped.append((rule["_path"], "auditd has no faithful Sentinel field mapping"))
            continue
        # Sigma unfielded keywords mean "anywhere in the event". KQL can only say
        # that with a table-wide `search`, which is not something to put in an
        # analytics rule, so this is a decline rather than a slower equivalent.
        det_blocks = selection_blocks(rule["detection"])
        if any(not f for b in det_blocks for f, _m, _v in iter_field_matches(b)):
            skipped.append((rule["_path"],
                            "unfielded keyword search has no faithful KQL field mapping"))
            continue
        det = rule["detection"]
        names = selection_names(det)
        tree = parse_condition(str(det["condition"]), names)

        def render(node) -> str:
            kind = node[0]
            if kind == "sel":
                block = det[node[1]]
                clauses = []
                for field, mods, values in iter_field_matches(block):
                    kf = resolve_field("sentinel", platform, field)
                    values, mods = expand_values(values, mods)
                    joiner = " and " if "all" in mods else " or "
                    clauses.append("(" + joiner.join(_kql_value(kf, v, mods) for v in values) + ")")
                return "(" + " and ".join(clauses) + ")" if clauses else "(true)"
            if kind == "not":
                return f"not {render(node[1])}"
            op = " and " if kind == "and" else " or "
            return "(" + op.join(render(c) for c in node[1:]) + ")"

        key = logsource_key(rule)
        table = SENTINEL_TABLES.get(key) or SENTINEL_TABLES.get((key[0], None), "SecurityEvent")
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
            by = resolve_field("sentinel", platform, agg["by"]) if agg.get("by") else "Computer"
            reducer = f"dcount({resolve_field('sentinel', platform, agg['field'])})" if agg["field"] else "count()"
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
        "filters": {"platforms": ["Windows", "Linux", "IaaS", "Office Suite", "Identity Provider", "SaaS"]},
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
        f"**{len({r['_tactic'] for r in rules})} tactics** on {', '.join(platforms[:-1]) + ' and ' + platforms[-1] if len(platforms) > 1 else platforms[0]}.",
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
# --------------------------------------------------------------------------
# Screening a corpus that is not ours
#
# Compiling this pack is all-or-nothing on purpose: a rule that cannot be
# translated faithfully is a CI failure, not a warning. Pointed at somebody
# elses corpus that is the wrong behaviour. Three thousand SigmaHQ rules will
# always contain constructs this compiler does not implement, and refusing to
# emit any of the other two thousand helps nobody. So: screen per rule, keep
# what translates, and say precisely why the rest did not.
# --------------------------------------------------------------------------
def _probe(rule: dict, backend: str) -> None:
    """Compile one rule for one backend, purely to find out whether it can be.

    The renderer is the oracle. Screening by re-implementing what the renderer
    accepts would eventually drift out of agreement with the renderer, which is
    the exact class of silently-wrong output this compiler exists to prevent."""
    if backend == "wazuh":
        render_wazuh([rule])
    elif backend == "splunk":
        render_splunk([rule])
    elif backend == "sentinel":
        _, declined = render_sentinel([rule])
        if declined:
            raise Unsupported(declined[0][1])
    # navigator, coverage, stats and validate render no fields, so parsing plus
    # the shared checks in validate() are the whole bar for those.


def screen(rules: list[dict], backend: str, strict: bool = False):
    """Split a corpus into what this backend can render faithfully, and the rest.

    Returns (translatable, [(path, reason)])."""
    ok, declined = [], []
    for rule in rules:
        if rule.get("_unreadable"):
            declined.append((rule["_path"], rule["_unreadable"]))
            continue
        if not strict:
            relax(rule)
        errs = validate(rule, strict=strict)
        if errs:
            declined.append((rule["_path"], errs[0]))
            continue
        try:
            _probe(rule, backend)
        except Unsupported as e:
            declined.append((rule["_path"], str(e)))
        except Exception as e:  # noqa: BLE001
            # A foreign corpus is adversarial input for a compiler this small.
            # An unexpected exception becomes a skip with its reason attached,
            # not a crash two thousand rules into somebody elses build.
            declined.append((rule["_path"], f"{type(e).__name__}: {e}"))
        else:
            ok.append(rule)
    return ok, declined


def _reason_bucket(reason: str) -> str:
    """Collapse a specific refusal into its class, so a report can rank causes
    instead of printing three thousand near-identical lines."""
    # Refusals raised from inside a renderer carry the rule path as a prefix.
    # Left in, every one of them buckets to itself and the ranking is useless.
    text = re.sub(r"^\S+\.ya?ml:\s*", "", str(reason))
    text = re.sub(r"'[^']*'", "'X'", text)
    text = re.sub(r'"[^"]*"', '"X"', text)
    text = re.sub(r"\b\d+\b", "N", text)
    text = text.split(";")[0].split(" (")[0].split(". ")[0].strip()
    return text[:110]


REPORT_BACKENDS = ("wazuh", "splunk", "sentinel")


def render_report(rules: list[dict], where: str, strict: bool = False) -> str:
    """How much of a given corpus this compiler can translate, and what stops
    the rest. Generated so the number is never a claim somebody has to trust."""
    unreadable = [r for r in rules if r.get("_unreadable")]
    readable = len(rules) - len(unreadable)

    out = [
        "# Sigma translation report",
        "",
        f"Corpus: `{where}`",
        "",
        f"- **{len(rules)} Sigma documents** found"
        + (f", {len(unreadable)} of which could not be parsed as YAML" if unreadable else ""),
        f"- **{readable} rules** offered to the compiler",
        "",
        "| Backend | Translated | Declined | Rate | Output rules |",
        "|---|---:|---:|---:|---:|",
    ]

    per_backend = {}
    for backend in REPORT_BACKENDS:
        ok, declined = screen([dict(r) for r in rules], backend, strict=strict)
        per_backend[backend] = declined
        emitted = len(ok)
        if backend == "wazuh" and ok:
            # A disjunction becomes one sibling Wazuh rule per branch, so the
            # count of rules on the manager is genuinely higher than the count
            # of sources. Worth stating rather than quietly conflating them.
            emitted = render_wazuh(ok).count("<rule id=")
        rate = f"{100 * len(ok) / readable:.0f}%" if readable else "n/a"
        out.append(f"| {backend} | {len(ok)} | {len(declined)} | {rate} | {emitted} |")

    techs = sorted({t for r in rules if not r.get("_unreadable") for t in techniques_of(r)})
    out += ["", f"ATT&CK techniques present in the corpus: **{len(techs)}**", ""]

    out.append("## Why rules were declined")
    out.append("")
    out.append("Every line here is the compiler refusing to emit something it could not")
    out.append("translate faithfully. A converter that silently degraded these instead")
    out.append("would report a higher number and ship rules that quietly mean something")
    out.append("other than their source.")
    for backend in REPORT_BACKENDS:
        declined = per_backend[backend]
        if not declined:
            continue
        buckets: dict = {}
        for _path, reason in declined:
            buckets.setdefault(_reason_bucket(reason), []).append(_path)
        out += ["", f"### {backend} ({len(declined)} declined)", "",
                "| Reason | Rules |", "|---|---:|"]
        for reason, paths in sorted(buckets.items(), key=lambda kv: -len(kv[1]))[:15]:
            out.append(f"| {reason.replace('|', chr(92) + '|')} | {len(paths)} |")
    out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compile Sigma rules to Wazuh, Splunk and Sentinel.",
        epilog=(
            "examples:\n"
            "  %(prog)s --backend wazuh --out dist/wazuh\n"
            "  %(prog)s --input ~/sigma/rules --backend wazuh --out /tmp/wazuh\n"
            "  %(prog)s --input ~/sigma/rules --backend report > REPORT.md\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--backend",
        choices=["wazuh", "splunk", "sentinel", "navigator", "coverage",
                 "validate", "stats", "report"],
        required=True,
        help="output dialect, or one of the reporting modes (validate, stats, report)",
    )
    ap.add_argument("--out", help="output directory (sentinel writes one file per rule)")
    ap.add_argument(
        "--input", nargs="+", metavar="PATH", default=None,
        help="Sigma files or directories to compile. Defaults to the rules in this "
             "pack. Point it at any Sigma corpus, for instance a SigmaHQ checkout.",
    )
    ap.add_argument(
        "--source-url", metavar="TEMPLATE",
        help="link template back to each original rule, with {path} standing in for the "
             "rule path relative to --input. For example "
             "https://github.com/SigmaHQ/sigma/blob/master/rules/{path}",
    )
    ap.add_argument(
        "--source-license", metavar="TEXT",
        help="license the source rules are under, named in the compiled output "
             "(for example \"the Detection Rule License 1.1\").",
    )
    ap.add_argument(
        "--source-name", metavar="TEXT",
        help="human name of the corpus being compiled, named in the compiled output.",
    )
    ap.add_argument(
        "--summary", metavar="PATH",
        help="write a JSON summary of the run (counts and refusal reasons) to PATH. "
             "Intended for CI, dashboards and tracking translation drift over time.",
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--strict", dest="strict", action="store_true", default=None,
        help="every rule must meet the house standards of this pack and translate to "
             "every backend, or the whole build fails. Default for the bundled rules.",
    )
    mode.add_argument(
        "--lax", dest="strict", action="store_false",
        help="keep the rules that translate, report the ones that do not, and exit 0. "
             "Default when --input is given, because a corpus you did not write will "
             "always contain constructs this compiler does not implement.",
    )
    args = ap.parse_args()
    # Installed with pip/uvx there is no bundled rules/ next to the module, so
    # say so instead of reporting "0 rules" as if the corpus were empty.
    if not args.input and not RULES_DIR.is_dir():
        ap.error("no --input given and no bundled rules/ directory found; "
                 "pass --input <dir of Sigma rules>")

    # Somebody elses rules are screened per rule; ours are all-or-nothing.
    strict = args.strict if args.strict is not None else (args.input is None)
    ATTRIBUTION["url_template"] = args.source_url
    ATTRIBUTION["license"] = args.source_license
    ATTRIBUTION["corpus"] = args.source_name
    where = ", ".join(args.input) if args.input else RULES_DIR.as_posix()

    rules = load_rules(args.input)
    if not rules:
        print(f"no Sigma rules found under {where}", file=sys.stderr)
        return 1

    if args.backend == "report":
        print(render_report(rules, where, strict=strict))
        return 0

    if strict:
        problems = {r["_path"]: validate(r) for r in rules}
        problems = {k: v for k, v in problems.items() if v}
        if problems:
            for path, errs in problems.items():
                for e in errs:
                    print(f"{path}: {e}", file=sys.stderr)
            if args.backend != "validate":
                return 1
        _write_summary(args.summary, args.backend, offered=len(rules),
                       declined=[(k, v[0]) for k, v in problems.items()])
        if args.backend == "validate":
            print(f"validated {len(rules)} rules, {len(problems)} with problems")
            return 1 if problems else 0
    else:
        offered = len(rules)
        rules, declined = screen(rules, args.backend, strict=False)
        for path, reason in declined:
            print(f"declined: {path}: {reason}", file=sys.stderr)
        print(f"{args.backend}: translated {len(rules)}/{offered} rules, "
              f"declined {len(declined)}", file=sys.stderr)
        _write_summary(args.summary, args.backend, offered=offered, declined=declined)
        if args.backend == "validate":
            return 0
        if not rules:
            print("nothing left to emit", file=sys.stderr)
            return 1

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


def _write_summary(path: "str | None", backend: str, offered: int, declined: list) -> None:
    """A machine-readable record of what translated and what did not.

    The point of publishing the refusals alongside the counts is that a rising
    `declined` number is information, not failure. It usually means the upstream
    corpus started using a construct this compiler does not implement yet."""
    if not path:
        return
    reasons: dict = {}
    for _rule_path, reason in declined:
        reasons[_reason_bucket(reason)] = reasons.get(_reason_bucket(reason), 0) + 1
    payload = {
        "backend": backend,
        "offered": offered,
        "translated": offered - len(declined),
        "declined": len(declined),
        "rate": round((offered - len(declined)) / offered, 4) if offered else None,
        "reasons": dict(sorted(reasons.items(), key=lambda kv: -kv[1])),
    }
    out = pathlib.Path(path)
    if out.parent != pathlib.Path(""):
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote summary to {out}", file=sys.stderr)


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
