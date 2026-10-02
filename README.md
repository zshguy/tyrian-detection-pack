# Tyrian Detection Pack

**3,600 SigmaHQ detections on your Wazuh manager in one `curl`. Plus the compiler that made them, which refuses to emit a rule that can never fire.**

[![validate + compile](https://github.com/zshguy/tyrian-detection-pack/actions/workflows/ci.yml/badge.svg)](https://github.com/zshguy/tyrian-detection-pack/actions/workflows/ci.yml)
[![SigmaHQ ruleset](https://github.com/zshguy/tyrian-detection-pack/actions/workflows/sigmahq-release.yml/badge.svg)](https://github.com/zshguy/tyrian-detection-pack/releases/tag/sigmahq-latest)
[![SigmaHQ coverage](https://img.shields.io/badge/SigmaHQ-96%25%20compiles%20to%20Wazuh-6d28d9)](#does-it-work-on-rules-that-are-not-ours)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

```bash
curl -LO https://github.com/zshguy/tyrian-detection-pack/releases/download/sigmahq-latest/sigmahq-wazuh-rules.xml
sudo cp sigmahq-wazuh-rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-control restart
```

That is the whole SigmaHQ corpus, converted, regenerated every Monday, with a
report of every rule that was refused and why. Splunk `.conf` and Sentinel KQL
are in [the same release](https://github.com/zshguy/tyrian-detection-pack/releases/tag/sigmahq-latest).

Rule IDs start at 100100. Check for collisions with your local rules, read the
report, and expect to tune. The rules remain the work of their SigmaHQ authors
under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License);
each compiled rule carries its author and a link back.

---

## Why this exists

Wazuh has no Sigma backend. pySigma, which maintains the backends everybody
else uses, [does not have one](https://github.com/SigmaHQ/pySigma/discussions/257).
So Wazuh operators hand-translate Sigma into `<field>` regex XML, and hand
translation is where detections die quietly: the rule loads, the manager is
healthy, and it can never match.

Every previous converter hit the same wall, and
[sigma_to_wazuh](https://github.com/theflakes/sigma_to_wazuh) says so in its own README:

> Some logic conversion is still broken due to the complexities of converting
> Sigma OR logic into Wazuh OR logic unfortunately.

A Wazuh rule is **one flat conjunction**. It cannot hold an `or`. Collapse a
disjunction into one rule and it silently becomes an `and`. Our own
shadow-copy deletion rule spent months requiring `Image` to be `vssadmin.exe`
*and* `wmic.exe` at the same time. It could never have fired, and nothing told us.

The fix is to rewrite the condition into disjunctive normal form and emit one
sibling rule per branch, which is why 3,144 Sigma rules come out as 3,609 Wazuh
rules. Everything else in this repo follows from taking that kind of failure
seriously.

## Six ways a detection looks fine and never fires

We audited our own compiler after shipping it. Every one of these was live in
`dist/` at some point, every one deployed cleanly, and every one now has a test.

| # | What the rule said | What actually got deployed | Why it never fired |
|---|---|---|---|
| 1 | `vssadmin.exe or wmic.exe` | `vssadmin.exe and wmic.exe` | Wazuh rules can't hold an `or` |
| 2 | `Image\|endswith: '\\powershell.exe'` | regex needing **two** backslashes | Sigma `\\` means one backslash; we escaped it twice |
| 3 | `CommandLine\|contains: '-EncodedCommand'` | case-sensitive PCRE | Sigma matching is case-insensitive; `-encodedcommand` walked past |
| 4 | `CommandLine has_any (" -enc", ...)` (Sentinel) | whole-term match | KQL `has_any` matches terms, not substrings; `-EncodedCommand` isn't the term `-enc` |
| 5 | `QueryName\|re: '[A-Za-z0-9]{40,}\\.'` | regex requiring a literal backslash | the rule file, not the compiler, escaped the dot twice |
| 6 | `DestinationIp\|cidr: 10.0.0.0/8` | `^10\.0\.0\.0/8$` as a literal | the modifier was silently dropped; no IP is spelled `10.0.0.0/8` |

If you run any Sigma-to-anything converter, go check your output for #2, #3 and #6.
They are the kind of bug a green CI run does not catch, because the file is
well-formed and the test suite is checking the shape of the XML, not whether a
real event would match it.

---

## Compile your own

No clone needed:

```bash
uvx --from git+https://github.com/zshguy/tyrian-detection-pack sigma-compile \
    --input /path/to/sigma/rules --backend wazuh --out ./wazuh
```

(`pipx run --spec git+https://github.com/zshguy/tyrian-detection-pack sigma-compile ...` works the same way.)

Or from a checkout:

```bash
git clone https://github.com/zshguy/tyrian-detection-pack
cd tyrian-detection-pack && pip install pyyaml

python tools/sigma_compile.py --backend wazuh --out dist/wazuh           # this pack
python tools/sigma_compile.py --input ~/sigma/rules --backend wazuh --out /tmp/wazuh   # any corpus
```

Backends: `wazuh`, `splunk`, `sentinel`, `navigator`, plus `report` for a
translation table and `validate` for a strict lint. MIT licensed. One file, one
dependency, no signup.

## Does it work on rules that are not ours

The interesting question about a converter is not whether it handles the corpus
it shipped with. So, against all of SigmaHQ:

| Backend | Translated | Declined | Rate | Rules emitted |
|---|---:|---:|---:|---:|
| Wazuh | 3,007 | 137 | **96%** | 3,609 |
| Splunk | 3,001 | 143 | **95%** | 3,001 |
| Sentinel | 2,862 | 282 | **91%** | 2,862 |

Run it yourself, it takes about a minute:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
python tools/sigma_compile.py --input /tmp/sigma/rules --backend report
```

**CI re-measures this against SigmaHQ `main` on every run** and publishes the
table to the job summary, because a number in a README is exactly the kind of
claim that rots quietly once upstream starts using constructs the compiler does
not implement.

The 137 refusals are the point, not an embarrassment. 110 of them are Sigma
rules that use `CommandLine` with `logsource.product: linux`, which is a
process-creation agent field. auditd has no command line at all (argv arrives
split across EXECVE `a0..aN`), so a converter that mapped it anyway would emit a
rule that deploys and can never match. This one says so instead:

```
field 'CommandLine' is not an auditd field. Linux rules compile against the
Wazuh auditd decoder, where a process argv arrives split across EXECVE a0..aN
and no single command line exists. A rule using 'CommandLine' with
logsource.product linux is written for a process-creation agent (Sysmon for
Linux, auditbeat), which this compiler does not map, so translating it would
produce a rule that deploys and never matches
```

## Use it in your own CI

If you maintain Sigma rules and run Wazuh, the compiler is a GitHub Action:

```yaml
- uses: zshguy/tyrian-detection-pack@v1
  with:
    rules: detections/
    backend: wazuh
    out: dist/wazuh
    strict: "true"     # fail the build on any rule that cannot be translated
```

It exposes `translated`, `declined` and `rate` as step outputs, writes a
breakdown to the job summary, and `--summary out.json` gives you the same data
on the command line for tracking translation drift over time.

---

## The corpus

90 rules, 83 ATT&CK techniques, 12 tactics, across Windows, Linux, macOS, AWS,
GCP, Entra ID, Microsoft 365, Okta and GitHub. Counts are generated, never hand-maintained. Full
per-rule table in [COVERAGE.md](COVERAGE.md).

| Tactic | Rules | Examples |
|---|---:|---|
| Credential Access | 19 | Kerberoasting, AS-REP roasting, DCSync, NTDS.dit, LSASS via `comsvcs.dll`, ADCS ESC1, shadow credentials, golden/silver ticket tooling, browser password stores, Entra password spray, MFA fatigue, Okta MFA factor reset |
| Persistence | 19 | Run keys, services, WMI subscriptions, AdminSDHolder, cron, systemd, `ld.so.preload`, AWS AdministratorAccess attached, Entra admin role assigned, app secrets added, mailbox FullAccess, GCP service-account key, GitHub org owner, macOS LaunchAgent |
| Defense Evasion | 12 | Event log cleared, Defender disabled, AMSI bypass, process hollowing, DCShadow, auditd tampering, CloudTrail / GuardDuty off, M365 audit log off |
| Lateral Movement | 8 | PsExec, pass-the-hash, WMI, WinRM, DCOM, admin-share writes, RDP enabled via registry, `tscon` session hijack |
| Execution | 8 | Encoded PowerShell, download cradles, `mshta`, Squiblydoo, `certutil`, Linux reverse shells, curl-pipe-bash, `osascript` admin prompt |
| Privilege Escalation | 7 | RBCD, unconstrained delegation, GPO modification, BYOVD, sudoers, container escape, logon type 9 |
| Initial Access | 4 | Office spawning a script host, web server spawning a shell, script run from a zip or Downloads, AWS root console login |
| Impact | 3 | Shadow-copy deletion, backup destruction, mass service stop |
| Command and Control | 3 | DNS tunneling, Cobalt Strike named pipes, BITS transfers |
| Collection | 2 | S3 public access block removed, M365 forwarding rules |
| Discovery | 3 | SharpHound collection, domain recon burst, Linux enumeration burst |
| Exfiltration | 2 | Archive staging, rclone to cloud storage |

Two things make this corpus worth having on top of SigmaHQ:

**Rules say whether they have ever fired.** The `stable` ones were written
against a live range: the attack was detonated, the telemetry captured, the rule
tuned against what actually appeared in the log. Rules that have not had that
treatment are marked `status: experimental` and say so in the file. A rule set
that lies about its own maturity is worse than one that is simply small.

**Every rule carries a way to trigger it.** "How do I test this?" usually has no
answer. Here it is a required field, and it travels into the compiled output, so
the answer is sitting in the rule when you are staring at it in Splunk at 2am:

```yaml
validation:
  atomic: T1558.003
  fire: |-
    Rubeus.exe kerberoast /rc4opsec
    GetUserSPNs.py -request <domain>/<user>
```

### ATT&CK Navigator

`dist/navigator/tyrian-detection-pack.json` is a Navigator layer. Open
[the Navigator](https://mitre-attack.github.io/attack-navigator/), choose "Open
Existing Layer" then "Upload from local", and you get the matrix scored by how
many rules cover each technique, with the rule names and their validation status
in the tooltip. Useful for spotting where coverage is one rule deep.

---

## What the compiler supports

It implements the subset of Sigma this corpus uses, strictly. Anything outside
that raises an error instead of emitting a wrong rule.

**Supported:** string/int/list values, `null`, unfielded keyword search, the
`contains` / `startswith` / `endswith` / `all` / `cased` / `windash` / `cidr`
modifiers, `re` with `i`/`m`/`s` flags, `base64` and `base64offset` with
`utf16le` / `utf16be` / `utf16` / `wide`, `1 of` and `all of` with `them` and
`prefix*`, `and` / `or` / `not`, parentheses, `*` and `?` wildcards, Sigma
escaping (`\\`, `\*`, `\?`), and `| count(field) by other > n` aggregation.

**Not supported (raises):** `near` correlation, `fieldref`, `exists`, numeric
comparisons, and any modifier not listed above. An unknown modifier is a hard
error, not a silently dropped one: `|cidr: 10.0.0.0/8` rendered as a literal is
a rule that deploys and never fires. Wazuh additionally refuses IPv6 and
non-octet-aligned IPv4 CIDRs rather than widening them to a prefix regex.

**Log sources:** Windows (Security, Sysmon, System, PowerShell), Linux auditd,
macOS (osquery `process_events` / `file_events` for Wazuh and Splunk, Defender
`DeviceProcessEvents` / `DeviceFileEvents` for Sentinel), AWS CloudTrail, GCP
Cloud Audit Logs, Entra ID sign-in and audit logs, Microsoft 365 / Exchange,
Okta System Log, GitHub audit log. Each one maps to the namespace its backend's
connector actually produces (`win.eventdata.*`, `audit.*`, `aws.*`, `gcp.*`,
`github.*`, `osquery.*`, `office365.*` in Wazuh; `AWSCloudTrail`, `GCPAuditLogs`,
`SigninLogs`, `OktaSSO`, `OfficeActivity` in Sentinel). An unknown log source is emitted
unscoped with a `TUNE:` note, never quietly scoped to Windows.

**Fields are resolved per platform, strictly.** Windows fields fall back to a
derived Sysmon name, which is correct for Sysmon's open-ended schema. Linux and
cloud have no such regular fallback, so an unmapped field is a hard error
naming the fields that do exist.

**Disjunctions become sibling Wazuh rules.** See above. Likewise `|all`
compiles to PCRE2 lookaheads rather than alternation, because alternation means
"any" and `all` means "all".

**Matching is case-insensitive unless you say otherwise.** Wazuh patterns are
emitted as PCRE2 with `(?i)` unless the modifier is `|cased` or `|re`, which is
what Sigma specifies and what most hand-written Wazuh rules get wrong.

**Unfielded keywords are not anchored.** Sigma keyword search means the value
appears somewhere in the event, so it compiles to an unanchored Wazuh `<regex>`
over the whole log, not `^value$` against a field that does not exist.

Aggregation is what most converters get wrong, so here is one rule in all three
dialects, compiled from a single source file:

```yaml
# rules/credential-access/password-spraying-4625.yml
condition: selection | count(TargetUserName) by IpAddress > 10
timeframe: 5m
```

```xml
<!-- Wazuh -->
<frequency>10</frequency>
<timeframe>300</timeframe>
<same_field>win.eventdata.ipAddress</same_field>
<different_field>win.eventdata.targetUserName</different_field>
```
```spl
| bucket _time span=5m | stats dc(TargetUserName) as hits by _time,IpAddress | where hits > 10
```
```kql
| summarize Hits=dcount(TargetUserName) by bin(TimeGenerated, 5m), IpAddress
| where Hits > 10
```

Each of the behaviours above has a test, because every one of them is a bug that
is silent in production:

```bash
python -m unittest discover -s tools -p "test_*.py" -v
```

---

## Linux rules need auditd configured

The Linux detections read auditd, and they key off audit rules that have to exist
before any of this produces a single event:

```bash
sudo cp deploy/audit.rules /etc/audit/rules.d/tyrian.rules
sudo augenrules --load
sudo auditctl -l | grep tyrian     # confirm
```

[`deploy/audit.rules`](deploy/audit.rules) explains the two decisions that matter:
watches are filtered to `auid>=1000` so daemon noise does not bury you, and
directory watches use `-p wa` rather than `-p r`, because a read watch on a busy
path is a self-inflicted outage.

**Linux rules compile for Wazuh and Splunk but not Sentinel.** auditd reaches
Sentinel as unparsed `Syslog` text unless you have built a custom table and DCR
for it, and `SyslogMessage contains "/usr/bin/nc"` is not the same detection as a
field match. The compiler declines rather than shipping something weaker that
looks equivalent, and lists what it skipped in
`dist/sentinel/_NOT_TRANSLATED.md`.

---

## Deploying

**Wazuh**, copy the generated rules onto the manager and restart:
```bash
cp dist/wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
/var/ossec/bin/wazuh-control restart
```
Agent-side config for the channels these rules need is in
[`deploy/ossec.conf.snippet`](deploy/ossec.conf.snippet): auditd collection for
the Linux rules, event channels for the Windows ones, and FIM for the encryption
rules. Most Windows rules assume **Sysmon** is installed and forwarding, and the
Active Directory rules need directory service auditing enabled on the DCs (and CA
auditing for the ADCS rules), neither of which is on by default. The cloud rules
need the matching Wazuh module (`aws-s3`, `azure-logs`, `office365`) configured.

**Splunk**, `dist/splunk/tyrian_detections.conf` has one stanza per rule. Adjust
the `index=` prefix for your environment.

**Sentinel**, `dist/sentinel/*.kql`, one file per rule, ready to paste into an
analytics rule.

Everything under [`dist/`](dist/) is already compiled and committed, so you can
copy-paste without running anything.

> Tune before you trust. Thresholds and paths here are starting points chosen in
> a lab, not for your estate. Anything marked `experimental` will be noisy
> somewhere.

### Your antivirus may eat the compiled rules

This is expected, and it is not a false alarm on their part. A compiled detection
contains the exact strings it hunts for, so
`dist/sentinel/powershell-download-cradle.kql` holds `DownloadString`,
`Net.WebClient` and `IEX` on one line. To a real-time scanner that reads like a
live download cradle, and Windows Defender will quarantine the file a second or
two after it is written.

Every detection repo hits this. The compiler checks for it rather than lying to
you: if a file disappears after being written it reports the name and exits `2`,
instead of printing "wrote 36" when 35 survived.

Options, in order of preference:

1. Build on Linux or WSL. CI does, which is why committed `dist/` is complete.
2. Add a Defender exclusion for the checkout:
   `Add-MpPreference -ExclusionPath C:\path\to\tyrian-detection-pack`
3. Use the `rules/` sources directly. They are never quarantined, because the
   attacker strings in a YAML list do not look like a payload to a scanner.

---

## Contributing

A new rule is one YAML file and takes about five minutes. The compiler lints it,
CI compiles it to every backend, and the coverage table updates itself.
[CONTRIBUTING.md](CONTRIBUTING.md) has the template and the house rules.

The most useful things you can do right now, in order:

1. **Fire an `experimental` rule on a range and tell us what happened.** 59 of
   the 90 have never seen a real event. Confirming one (or finding it broken)
   is worth more than writing three new ones. Use the
   [missed detection](.github/ISSUE_TEMPLATE/missed-detection.yml) or
   [false positive](.github/ISSUE_TEMPLATE/false-positive.yml) template.
2. **Check a field name against a real event.** The Okta, GCP, GitHub and
   macOS maps were written from connector documentation, not from decoded
   alerts. One pasted alert confirms or corrects an entire log source.
3. **Implement `fieldref` or `near`.** The last Sigma constructs the compiler
   refuses. Both need a design, not just code; open an issue first.

If this saved you a toolchain, a star helps the next Wazuh operator find it.

## Related

Built by [Tyrian](https://tyriancyber.com), a purple-team cyber range that spins
up a real AD environment plus a Wazuh SIEM so you can fire these techniques and
watch which of your rules catch them. Technique write-ups with the telemetry
behind each rule: [tyriancyber.com/attack](https://tyriancyber.com/attack).

The rules are useful on their own. That is the point of publishing them.

---

## License

MIT for everything in this repo. Compiled SigmaHQ output in the releases is
under the Detection Rule License 1.1, same as the source rules.
