# Security

## What counts as a security issue here

This repo ships detection rules and a compiler. The failure modes that matter:

- **A compiled rule that is syntactically valid but can never match** the
  behaviour its source rule describes. This is the bug class the project
  exists to prevent; please report it as a bug, not a vulnerability, using the
  [missed detection](.github/ISSUE_TEMPLATE/missed-detection.yml) template so
  it is public and fixed quickly.
- **Compiled output that breaks a manager.** Wazuh rejects the whole of
  `local_rules.xml` on one parse error. CI parses every published file, but if
  you find a rule that loads and then crashes or hangs `wazuh-analysisd`,
  report it privately (below) so it can be pulled from the release first.
- **A compiler input that executes code.** The compiler reads YAML with
  `yaml.safe_load` and never evaluates rule content. If you find a way to make
  it do otherwise, report it privately.

## Reporting privately

Use GitHub's private vulnerability reporting on this repository
(Security tab, "Report a vulnerability"). Expect an acknowledgement within a
few days. There is no bounty.

## Scope notes

- The weekly SigmaHQ release compiles rules written by third parties. A
  malicious or broken upstream rule is reported to SigmaHQ; a compiler that
  mistranslates it is reported here.
- Detection rules are not a security boundary. A rule that is bypassable is a
  rule to improve, not a vulnerability.
