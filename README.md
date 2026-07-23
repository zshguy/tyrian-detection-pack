# Tyrian Detection Pack

A free, open set of detection rules for the ATT&CK techniques that show up in real
intrusions, in both [Sigma](https://github.com/SigmaHQ/sigma) and
[Wazuh](https://wazuh.com/) form. Clone it, drop the rules into your SIEM, and
you have same-day coverage for kerberoasting, LSASS dumping, PsExec lateral
movement, ransomware encryption, and phishing macro execution.

Every rule here is one we run against a live range, so the telemetry it keys on is
real, not remembered. If you want to see a rule fire before you trust it in
production, you can launch the exact scenario that triggers it on
**[Tyrian](https://tyriancyber.com)** (a purple-team cyber range you rent by the
hour, $5 free credit to start).

## What's inside

| Technique | ATT&CK | Sigma | Wazuh |
|---|---|---|---|
| Kerberoasting (RC4 TGS) | T1558.003 | `sigma/kerberoasting-rc4-tgs.yml` | `wazuh/local_rules.xml` |
| LSASS memory dumping | T1003.001 | `sigma/lsass-handle-access.yml` | `wazuh/local_rules.xml` |
| PsExec / SMB lateral movement | T1021.002 | `sigma/psexec-service-creation.yml` | `wazuh/local_rules.xml` |
| Ransomware encryption | T1486 / T1490 | `sigma/ransomware-shadowcopy-deletion.yml` | `wazuh/local_rules.xml` |
| Phishing macro execution | T1566.001 | `sigma/office-spawns-script-host.yml` | `wazuh/local_rules.xml` |

## Requirements

These rules assume you are collecting the right telemetry. Most of it is free:

- **Sysmon** on Windows endpoints (use a good config like
  [SwiftOnSecurity's](https://github.com/SwiftOnSecurity/sysmon-config) or
  [Olaf Hartong's modular config](https://github.com/olafhartong/sysmon-modular)).
  You need at least Event IDs 1 (process create), 3 (network), 10 (process access),
  and 11 (file create).
- **Windows Security auditing** for Kerberos (4769) and logon (4624) events, and
  **System** log for service installs (7045).
- For the ransomware rule, **file integrity monitoring** on the directories you
  care about.

## Using the Sigma rules

The `sigma/` rules are standard Sigma. Convert them to your backend with
[sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
pip install sigma-cli
sigma convert -t splunk -p sysmon sigma/lsass-handle-access.yml
sigma convert -t elasticsearch sigma/kerberoasting-rc4-tgs.yml
```

Backends exist for Splunk, Elastic, Microsoft Sentinel, QRadar, and more.

## Using the Wazuh rules

Copy the rules from `wazuh/local_rules.xml` into your manager's
`/var/ossec/etc/rules/local_rules.xml`, keeping the rule IDs in the `100xxx` range
(the local range Wazuh reserves for you). For the ransomware FIM rule, add the
`<syscheck>` block from `wazuh/ossec.conf.snippet` to your `ossec.conf`. Then:

```bash
/var/ossec/bin/wazuh-control restart
```

Tune the `filter_*` and `frequency`/`timeframe` values to your environment before
you rely on them, especially the LSASS rule (exclude your own EDR/AV) and the
ransomware burst thresholds.

## Test before you trust

A detection you haven't seen fire is a hypothesis. Each rule here maps to a live
Tyrian scenario you can launch in your browser to generate the real telemetry and
confirm the rule catches it, then measure how long detection took:

- Kerberoasting → **Kerberoast to Domain Admin**
- LSASS / PsExec / phishing → **Phishing to Lateral Movement**
- Ransomware → **Ransomware Detection & Recovery**

Start at [tyriancyber.com](https://tyriancyber.com).

## License

MIT. Use them, change them, ship them in your product. Attribution appreciated but
not required. Contributions welcome, open a PR with a rule and the telemetry it
needs.

## Disclaimer

These rules are a starting point, not a guarantee. Detection efficacy depends on
your logging, your environment, and your tuning. Test in a lab (like the one above)
before depending on any rule in production.
