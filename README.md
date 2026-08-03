# Tyrian Detection Pack

**Write the detection once. Get Wazuh, Splunk and Sentinel out of it.**

A curated corpus of ATT&CK-mapped detections in Sigma, plus a compiler that emits
working rules for three SIEMs. Every rule is validated in CI, carries a command
that triggers it, and says honestly whether it has been fired on a live range or
only reasoned about.

MIT licensed. No signup, no gated download, no "request a demo" wall.

```bash
git clone https://github.com/zshguy/tyrian-detection-pack
cd tyrian-detection-pack && pip install pyyaml

python tools/sigma_compile.py --backend wazuh     --out dist/wazuh
python tools/sigma_compile.py --backend splunk    --out dist/splunk
python tools/sigma_compile.py --backend sentinel  --out dist/sentinel
python tools/sigma_compile.py --backend navigator --out dist/navigator
```

Already compiled and committed under [`dist/`](dist/) if you just want to copy-paste.
Full breakdown in [COVERAGE.md](COVERAGE.md), which is generated, never hand-maintained.

---

## Why this exists

There is no shortage of Sigma rules. There are two shortages:

**1. Nobody maintains a good Sigma to Wazuh path.** pySigma has solid Splunk and
Sentinel backends. Wazuh, which a very large number of small teams and MSSPs
actually run, leaves you translating Sigma into `<field>` regex XML by hand. That
translation is where the bugs live. `tools/sigma_compile.py` does it for you, and
refuses to emit a rule it cannot translate faithfully rather than quietly
producing one that means something subtly different.

**2. Most public rules have never been fired in anger.** The `stable` rules here
were written against a live range: the attack was detonated, the telemetry
captured, the rule tuned against what actually appeared in the log. Rules that
have not had that treatment are marked `status: experimental` and say so in the
file. There is no prize for pretending otherwise, and a rule set that lies about
its own maturity is worse than one that is simply small.

**3. "How do I test this?" usually has no answer.** Every rule in this pack
carries a `validation:` block: the Atomic Red Team technique it corresponds to,
and a command that produces the telemetry it matches. That travels into the
compiled output too, so the answer is sitting in the rule when you are staring at
it in Splunk at 2am.

```yaml
validation:
  atomic: T1558.003
  fire: |-
    Rubeus.exe kerberoast /rc4opsec
    GetUserSPNs.py -request <domain>/<user>
```

---

## Coverage

67 rules, 64 ATT&CK techniques, 11 tactics, Windows and Linux. Counts are
generated, never hand-maintained. See [COVERAGE.md](COVERAGE.md) for the full
per-rule table:

```bash
python tools/sigma_compile.py --backend stats
python tools/sigma_compile.py --backend coverage   # regenerates COVERAGE.md
```

| Tactic | Rules | Examples |
|---|---:|---|
| Credential Access | 14 | Kerberoasting, AS-REP roasting, DCSync, NTDS.dit, LSASS via `comsvcs.dll`, SAM hive dump, **ADCS ESC1 SAN abuse**, **shadow credentials**, **krbtgt reset**, **/etc/shadow access** |
| Persistence | 12 | Run keys, services, WMI subscriptions, scheduled tasks, **AdminSDHolder**, **cron**, **systemd units**, **authorized_keys**, **ld.so.preload**, **kernel modules** |
| Defense Evasion | 10 | Event log cleared, Defender disabled, AMSI bypass, **process injection**, **process hollowing**, **rundll32 abuse**, **DCShadow**, **auditd tampering**, **/var/log deletion** |
| Execution | 7 | Encoded PowerShell, download cradles, `mshta`, Squiblydoo, `certutil`, **Linux reverse shells**, **curl-pipe-bash** |
| Lateral Movement | 6 | PsExec, pass-the-hash, WMI, WinRM, DCOM, admin-share writes |
| Privilege Escalation | 6 | **RBCD**, **unconstrained delegation**, **GPO modification**, **BYOVD drivers**, **sudoers**, **container escape** |
| Impact | 3 | Shadow-copy deletion, backup destruction, mass service stop |
| Command and Control | 3 | DNS tunneling, **Cobalt Strike named pipes**, **BITS transfers** |
| Discovery | 3 | SharpHound collection, domain recon burst, **Linux enumeration burst** |
| Exfiltration | 2 | Archive staging, **rclone to cloud storage** |
| Initial Access | 1 | Office spawning a script host |

Bold entries are new. The Linux rules are the notable gap-fill: Wazuh's user base
is overwhelmingly Linux, and a "Wazuh-first" detection pack that only shipped
Windows rules was a strange thing to be.

### ATT&CK Navigator

`dist/navigator/tyrian-detection-pack.json` is a Navigator layer. Open
[the Navigator](https://mitre-attack.github.io/attack-navigator/), choose "Open
Existing Layer" then "Upload from local", and you get the matrix scored by how
many rules cover each technique, with the rule names and their validation status
in the tooltip. Useful for spotting where coverage is one rule deep.

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

## What the compiler supports

It implements the subset of Sigma this corpus uses, strictly. Anything outside
that raises an error instead of emitting a wrong rule.

**Supported:** string/int/list values, `null`, the `contains` / `startswith` /
`endswith` / `re` / `all` / `cased` modifiers, `1 of` and `all of` with `them`
and `prefix*`, `and` / `or` / `not`, parentheses, `*` and `?` wildcards, and
`| count(field) by other > n` aggregation.

**Not supported (raises):** `near` correlation, `base64offset`, `utf16`, `cidr`.

**Fields are resolved per platform, strictly.** Windows fields fall back to a
derived Sysmon name, which is correct for Sysmon's open-ended schema. Linux has no
such regular fallback, so an unmapped field is a hard error naming the fields that
do exist. This matters more than it sounds: auditd has no `CommandLine` (`comm` is
just the process name, and real argv arrives split across EXECVE `a0..aN`), so a
Linux rule written with Windows field names would compile, deploy, and match
nothing. Now it refuses:

```
rules/execution/linux-reverse-shell.yml: field 'CommandLine' has no wazuh mapping
for linux; add it to WAZUH_LINUX_FIELDS or use one of ['AuditKey', 'Comm',
'ExecveA0', 'ExecveA1', 'ExecveA2', ...]
```

**Disjunctions become sibling Wazuh rules.** A Wazuh rule is one flat conjunction
of `<field>` tests, so it cannot hold an `or`. The compiler rewrites the condition
into disjunctive normal form and emits one rule per branch. Before this, `a or b`
silently collapsed into `a and b`, which produced rules that could never fire (the
shadow-copy deletion rule wanted `Image` to be `vssadmin.exe` *and* `wmic.exe`
simultaneously). Likewise `|all` now compiles to PCRE2 lookaheads rather than
regex alternation, because alternation means "any" and `all` means "all".

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
```
```spl
| bucket _time span=5m | stats dc(TargetUserName) as hits by _time,IpAddress | where hits > 10
```
```kql
| summarize Hits=dcount(TargetUserName) by bin(TimeGenerated, 5m), IpAddress
| where Hits > 10
```

---

## Deploying

**Wazuh** — copy the generated rules onto the manager and restart:
```bash
cp dist/wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
/var/ossec/bin/wazuh-control restart
```
Agent-side config for the channels these rules need is in
[`deploy/ossec.conf.snippet`](deploy/ossec.conf.snippet): auditd collection for
the Linux rules, event channels for the Windows ones, and FIM for the encryption
rules. Most Windows rules assume **Sysmon** is installed and forwarding, and the
Active Directory rules need directory service auditing enabled on the DCs (and CA
auditing for the ADCS rules), neither of which is on by default.

**Splunk** — `dist/splunk/tyrian_detections.conf` has one stanza per rule.
Adjust the `index=` prefix for your environment.

**Sentinel** — `dist/sentinel/*.kql`, one file per rule, ready to paste into an
analytics rule.

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
   attacker strings are split across YAML list items rather than concatenated
   into one query line.

Do not "fix" this by obfuscating rule content. A detection you had to hide from
your own scanner is a detection you can no longer read or review.

---

## Contributing

Rules live in `rules/<tactic>/<name>.yml` and need a `title`, `id`,
`description`, `logsource`, `detection`, `level`, `validation`, and at least one
`attack.tNNNN` tag. CI validates every rule, recompiles every backend, and
regenerates `dist/` and `COVERAGE.md` itself, so you never have to.

```bash
python tools/sigma_compile.py --backend validate
```

Validation checks more than presence: the condition has to parse, and every field
has to resolve on every backend that will render it.

The bar for a new rule is **honesty about evidence**. If you detonated it and
tuned against the event, mark it `stable` and say what generated the telemetry.
If you reasoned it out from the data source, mark it `experimental` and fill in
`validation.fire` with the command that would prove it. Both are welcome. What
rots a rule set is `stable` on something nobody ever ran.

---

## Related

Built by [Tyrian](https://tyriancyber.com), a purple-team cyber range that spins
up a real AD environment plus a Wazuh SIEM so you can fire these techniques and
watch which of your rules catch them. Technique write-ups with the telemetry
behind each rule: [tyriancyber.com/attack](https://tyriancyber.com/attack).

The rules are useful on their own. That is the point of publishing them.
