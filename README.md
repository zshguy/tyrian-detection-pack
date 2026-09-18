# Tyrian Detection Pack

**Sigma detections, compiled to Wazuh properly.**

[![validate + compile](https://github.com/zshguy/tyrian-detection-pack/actions/workflows/ci.yml/badge.svg)](https://github.com/zshguy/tyrian-detection-pack/actions/workflows/ci.yml)
[![SigmaHQ ruleset](https://github.com/zshguy/tyrian-detection-pack/actions/workflows/sigmahq-release.yml/badge.svg)](https://github.com/zshguy/tyrian-detection-pack/releases/tag/sigmahq-latest)
[![SigmaHQ coverage](https://img.shields.io/badge/SigmaHQ-96%25%20compiles%20to%20Wazuh-6d28d9)](#does-it-work-on-rules-that-are-not-ours)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## Get 3,600 SigmaHQ detections onto your Wazuh manager

Wazuh has no Sigma backend, so getting community detections into it normally
means building a toolchain first. Here is the corpus already converted:

```bash
curl -LO https://github.com/zshguy/tyrian-detection-pack/releases/download/sigmahq-latest/sigmahq-wazuh-rules.xml
sudo cp sigmahq-wazuh-rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-control restart
```

[**Download the ruleset**](https://github.com/zshguy/tyrian-detection-pack/releases/tag/sigmahq-latest)
(Splunk `.conf` and Sentinel KQL are in the same release). Regenerated weekly
from SigmaHQ `master`, with a translation report listing every rule that was
refused and why.

That is a lot of detections to switch on at once. Rule IDs start at 100100, so
check for collisions with local rules you already have, read the report, and
expect to tune. The rules remain the work of their SigmaHQ authors under the
[Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License);
each compiled rule carries its author and a link back to the original.

---

## Or compile your own

```bash
git clone https://github.com/zshguy/tyrian-detection-pack
cd tyrian-detection-pack && pip install pyyaml

# The rules in this repo
python tools/sigma_compile.py --backend wazuh --out dist/wazuh

# Or any Sigma corpus at all
python tools/sigma_compile.py --input /path/to/sigma/rules --backend wazuh --out dist/wazuh
```

Backends: `wazuh`, `splunk`, `sentinel`, `navigator`. MIT licensed. No signup,
no gated download, no "request a demo" wall.

---

## Why another one of these

pySigma, which maintains the backends most people use, has
[no Wazuh backend](https://github.com/SigmaHQ/pySigma/discussions/257). So Wazuh
operators hand-translate Sigma into `<field>` regex XML, and hand translation is
where detections die quietly: the rule loads, the manager is healthy, and it can
never match.

**Prior art, because this is not a new idea.**
[theflakes/sigma_to_wazuh](https://github.com/theflakes/sigma_to_wazuh) is the
most complete previous attempt and is worth your time; its author has since
moved to a Go rewrite, [StoW](https://github.com/theflakes/StoW).
[sigWah](https://github.com/SanWieb/sigWah) did the same job in 2020 and is
archived. All of them run into the same wall, and `sigma_to_wazuh` says so in
its own README:

> Some logic conversion is still broken due to the complexities of converting
> Sigma OR logic into Wazuh OR logic unfortunately.

That wall is the problem worth solving. A Wazuh rule is **one flat conjunction**
of `<field>` tests, so it cannot hold an `or` at all. Collapse a disjunction into
one rule and it silently becomes an `and`: our own shadow-copy deletion rule
spent months requiring `Image` to be `vssadmin.exe` *and* `wmic.exe`
simultaneously. It could never have fired.

The fix is to rewrite the condition into disjunctive normal form and emit one
sibling rule per branch, which is why 3,144 Sigma rules come out as 3,633 Wazuh
rules. Everything else here follows from taking that kind of failure seriously.

---

## Does it work on rules that are not ours

The interesting question about a converter is not whether it handles the corpus
it shipped with. So, against all of SigmaHQ:

| Backend | Translated | Declined | Rate | Rules emitted |
|---|---:|---:|---:|---:|
| Wazuh | 3,028 | 116 | **96%** | 3,633 |
| Splunk | 3,027 | 117 | **96%** | 3,027 |
| Sentinel | 2,876 | 268 | **91%** | 2,876 |

Run it yourself, it takes about a minute:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
python tools/sigma_compile.py --input /tmp/sigma/rules --backend report
```

**CI re-measures this against SigmaHQ `main` on every run** and publishes the
table to the job summary, because a number in a README is exactly the kind of
claim that rots quietly once upstream starts using constructs the compiler does
not implement.

The 116 refusals are the point, not an embarrassment. 110 of them are Sigma
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

---

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

67 rules, 64 ATT&CK techniques, 11 tactics, Windows and Linux. Counts are
generated, never hand-maintained. Full per-rule table in [COVERAGE.md](COVERAGE.md).

| Tactic | Rules | Examples |
|---|---:|---|
| Credential Access | 14 | Kerberoasting, AS-REP roasting, DCSync, NTDS.dit, LSASS via `comsvcs.dll`, SAM hive dump, ADCS ESC1 SAN abuse, shadow credentials, krbtgt reset, `/etc/shadow` access |
| Persistence | 12 | Run keys, services, WMI subscriptions, scheduled tasks, AdminSDHolder, cron, systemd units, `authorized_keys`, `ld.so.preload`, kernel modules |
| Defense Evasion | 10 | Event log cleared, Defender disabled, AMSI bypass, process injection, process hollowing, rundll32 abuse, DCShadow, auditd tampering, `/var/log` deletion |
| Execution | 7 | Encoded PowerShell, download cradles, `mshta`, Squiblydoo, `certutil`, Linux reverse shells, curl-pipe-bash |
| Lateral Movement | 6 | PsExec, pass-the-hash, WMI, WinRM, DCOM, admin-share writes |
| Privilege Escalation | 6 | RBCD, unconstrained delegation, GPO modification, BYOVD drivers, sudoers, container escape |
| Impact | 3 | Shadow-copy deletion, backup destruction, mass service stop |
| Command and Control | 3 | DNS tunneling, Cobalt Strike named pipes, BITS transfers |
| Discovery | 3 | SharpHound collection, domain recon burst, Linux enumeration burst |
| Exfiltration | 2 | Archive staging, rclone to cloud storage |
| Initial Access | 1 | Office spawning a script host |

Two things make this corpus worth having on top of SigmaHQ:

**Rules say whether they have ever fired.** The `stable` ones were written
against a live range: the attack was detonated, the telemetry captured, the rule
tuned against what actually appeared in the log. Rules that have not had that
treatment are marked `status: experimental` and say so in the file. There is no
prize for pretending otherwise, and a rule set that lies about its own maturity
is worse than one that is simply small.

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
`contains` / `startswith` / `endswith` / `re` / `all` / `cased` modifiers, `1 of`
and `all of` with `them` and `prefix*`, `and` / `or` / `not`, parentheses, `*`
and `?` wildcards, and `| count(field) by other > n` aggregation.

**Not supported (raises):** `near` correlation, `base64offset`, `utf16`, `cidr`.

**Fields are resolved per platform, strictly.** Windows fields fall back to a
derived Sysmon name, which is correct for Sysmon's open-ended schema. Linux has
no such regular fallback, so an unmapped field is a hard error naming the fields
that do exist. Lookup is case-insensitive, because Sigma auditd rules spell
fields the way auditd does (`type`, `exe`, `a0`) and refusing a rule over a
capital letter helps nobody.

**Disjunctions become sibling Wazuh rules.** A Wazuh rule is one flat
conjunction of `<field>` tests, so it cannot hold an `or`. The compiler rewrites
the condition into disjunctive normal form and emits one rule per branch. Before
this, `a or b` silently collapsed into `a and b`, which produced rules that could
never fire (the shadow-copy deletion rule wanted `Image` to be `vssadmin.exe`
*and* `wmic.exe` simultaneously). Likewise `|all` compiles to PCRE2 lookaheads
rather than regex alternation, because alternation means "any" and `all` means
"all".

**Unfielded keywords are not anchored.** Sigma keyword search means the value
appears somewhere in the event, so it compiles to an unanchored Wazuh `<regex>`
over the whole log, not `^value$` against a field that does not exist.

**An unknown logsource is not quietly scoped to Windows.** A rule whose product
has no Wazuh group mapping is emitted with no `<if_group>` and a `TUNE:` note,
rather than being scoped to Windows events where it could never match.

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
auditing for the ADCS rules), neither of which is on by default.

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
python -m unittest discover -s tools -p "test_*.py"
```

Validation checks more than presence: the condition has to parse, and every field
has to resolve on every backend that will render it.

The bar for a new rule is **honesty about evidence**. If you detonated it and
tuned against the event, mark it `stable` and say what generated the telemetry.
If you reasoned it out from the data source, mark it `experimental` and fill in
`validation.fire` with the command that would prove it. Both are welcome. What
rots a rule set is `stable` on something nobody ever ran.

**A missing field mapping is a good first issue.** If the compiler refuses one of
your rules with "has no wazuh mapping", the fix is usually one line in the field
table, and that fix helps everyone pointing the compiler at the same log source.

---

## Related

Built by [Tyrian](https://tyriancyber.com), a purple-team cyber range that spins
up a real AD environment plus a Wazuh SIEM so you can fire these techniques and
watch which of your rules catch them. Technique write-ups with the telemetry
behind each rule: [tyriancyber.com/attack](https://tyriancyber.com/attack).

The rules are useful on their own. That is the point of publishing them.
