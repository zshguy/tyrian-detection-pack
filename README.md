# Tyrian Detection Pack

**Write the detection once. Get Wazuh, Splunk and Sentinel out of it.**

A curated corpus of ATT&CK-mapped detections in Sigma, plus a compiler that emits
working rules for three SIEMs. Every rule is validated in CI, and the stable ones
were written against telemetry from a real attack rather than from documentation.

MIT licensed. No signup, no gated download, no "request a demo" wall.

```bash
git clone https://github.com/zshguy/tyrian-detection-pack
cd tyrian-detection-pack && pip install pyyaml

python tools/sigma_compile.py --backend wazuh    --out dist/wazuh
python tools/sigma_compile.py --backend splunk   --out dist/splunk
python tools/sigma_compile.py --backend sentinel --out dist/sentinel
```

Already compiled and committed under [`dist/`](dist/) if you just want to copy-paste.

---

## Why this exists

There is no shortage of Sigma rules. There are two shortages:

**1. Nobody maintains a good Sigma to Wazuh path.** pySigma has solid Splunk and
Sentinel backends. Wazuh, which a very large number of small teams and MSSPs
actually run, leaves you translating Sigma into `<field>` regex XML by hand. That
translation is where the bugs live. `tools/sigma_compile.py` does it for you, and
refuses to emit a rule it cannot translate faithfully rather than quietly
producing one that means something subtly different.

**2. Most public rules have never been fired in anger.** These were written
against a live range: the attack was detonated, the telemetry captured, the rule
tuned against what actually appeared in the log. Where a rule is still
theoretical it is marked `status: experimental` and says so in the file.

---

## Coverage

36 rules, 33 ATT&CK techniques, 10 tactics. Counts are generated, never
hand-maintained:

```bash
python tools/sigma_compile.py --backend stats
```

| Tactic | Rules | Examples |
|---|---:|---|
| Credential Access | 9 | Kerberoasting (RC4 TGS), AS-REP roasting, DCSync, NTDS.dit extraction, LSASS via `comsvcs.dll`, SAM hive dump, WDigest cleartext staging |
| Lateral Movement | 6 | PsExec service creation, pass-the-hash, WMI remote exec, WinRM, DCOM, admin-share writes |
| Execution | 5 | Encoded PowerShell, download cradles, `mshta`, Squiblydoo, `certutil` as downloader |
| Persistence | 5 | Run keys, service from suspicious path, WMI event subscription, scheduled tasks, privileged group changes |
| Defense Evasion | 3 | Event log cleared, Defender disabled, AMSI bypass |
| Impact | 3 | Shadow-copy deletion, backup destruction, mass service stop |
| Discovery | 2 | SharpHound collection, domain recon burst |
| Initial Access | 1 | Office spawning a script host |
| Command and Control | 1 | DNS tunneling via long queries |
| Exfiltration | 1 | Archive staging |

---

## What the compiler supports

It implements the subset of Sigma this corpus uses, strictly. Anything outside
that raises an error instead of emitting a wrong rule.

**Supported:** string/int/list values, `null`, the `contains` / `startswith` /
`endswith` / `re` / `all` / `cased` modifiers, `1 of` and `all of` with `them`
and `prefix*`, `and` / `or` / `not`, parentheses, `*` and `?` wildcards, and
`| count(field) by other > n` aggregation.

**Not supported (raises):** `near` correlation, `base64offset`, `utf16`, `cidr`.

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
[`deploy/ossec.conf.snippet`](deploy/ossec.conf.snippet). Most Windows rules
assume **Sysmon** is installed and forwarding.

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
`description`, `logsource`, `detection`, `level`, and at least one
`attack.tNNNN` tag. CI validates every rule, recompiles all three backends, and
fails if `dist/` has drifted from `rules/`.

```bash
python tools/sigma_compile.py --backend validate
```

The bar for a new rule is **evidence**: say what generated the telemetry you
tuned against. "Detonated in a lab, here is the event" is enough. "Looks right"
is not, and is how rule sets rot.

---

## Related

Built by [Tyrian](https://tyriancyber.com), a purple-team cyber range that spins
up a real AD environment plus a Wazuh SIEM so you can fire these techniques and
watch which of your rules catch them. Technique write-ups with the telemetry
behind each rule: [tyriancyber.com/attack](https://tyriancyber.com/attack).

The rules are useful on their own. That is the point of publishing them.
