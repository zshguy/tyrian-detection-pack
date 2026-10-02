# Contributing

Three kinds of contribution, in order of how much they help:

1. **Validation reports.** Fire a rule on a range, tell us whether it matched.
   Open a [missed detection](.github/ISSUE_TEMPLATE/missed-detection.yml) or
   [false positive](.github/ISSUE_TEMPLATE/false-positive.yml) issue. If it
   fired cleanly, say so in a one-line PR that flips `status: experimental` to
   `status: stable` and names the tool you used.
2. **New rules.** One YAML file. Template below.
3. **Compiler work.** New log sources, new Sigma modifiers. See the bottom.

## Adding a rule

Copy this into `rules/<tactic>/<short-name>.yml`. The directory name is the
tactic, and the compiler uses it.

```yaml
title: Short, Specific Title
id: 00000000-0000-0000-0000-000000000000     # any UUID; `python -c "import uuid; print(uuid.uuid4())"`
status: experimental                          # stable only once it has fired on a range
description: >
  One paragraph. What behaviour this catches, which event it reads, and what
  makes the match specific enough to be worth an alert.
references:
  - https://attack.mitre.org/techniques/T1234/
author: you
date: 2026/10/02
logsource:
  product: windows          # windows | linux | aws | azure | m365
  service: sysmon           # security | sysmon | system | powershell | auditd | cloudtrail | signinlogs | auditlogs | exchange
detection:
  selection:
    Image|endswith: '\evil.exe'
    CommandLine|contains:
      - '-bad'
      - '-worse'
  filter_known:
    ParentImage|endswith: '\legit-updater.exe'
  condition: selection and not filter_known
validation:
  atomic: T1234             # the Atomic Red Team technique folder
  fire: |-
    evil.exe -bad           # a command a reader can actually run
falsepositives:
  - Who legitimately does this, and how to allowlist them
level: high                 # informational | low | medium | high | critical
tags:
  - attack.execution
  - attack.t1234
```

Then:

```bash
python tools/sigma_compile.py --backend validate     # strict lint, names the problem
python -m unittest discover -s tools -p "test_*.py"  # the bundled-corpus tests load every rule
```

Do **not** commit `dist/` or `COVERAGE.md`. CI regenerates both on merge. (If
you are on Windows, Defender will quarantine the compiled output anyway; see
the README.)

### House rules the linter enforces

- `validation.fire` is required and must be a command, not a sentence. A rule
  nobody can trigger is a rule nobody can trust.
- `validation.atomic` must be an ATT&CK technique id.
- At least one `attack.tNNNN` tag.
- Every field must resolve on every backend. Linux and cloud fields are strict:
  an unmapped field is an error naming the fields that do exist. If the field
  you need is missing, add it to the mapping table in `tools/sigma_compile.py`
  in the same PR.
- `status: stable` means the rule was fired on a live system and tuned against
  what appeared in the log. If you have not done that, it is `experimental`.
  There is no prize for pretending otherwise.

### Things that make a rule better

- Prefer `|endswith: '\name.exe'` over `|contains: 'name.exe'` for image
  paths. The latter matches `name.exe.config`.
- Prefer a `filter_*` selection over a narrower `selection`. The filter is
  where operators will add their own exclusions.
- One backslash means one backslash. Sigma's `\\` escape is accepted but not
  needed; `'\evil.exe'` and `'\\evil.exe'` compile identically.
- If the rule needs a threshold, use `condition: selection | count(Field) by Other > N`
  with a `timeframe:`. All three backends understand it.
- Say in `falsepositives` who legitimately does this. "None" is almost never true.

## Adding a log source

Each product needs, in `tools/sigma_compile.py`:

1. A field mapping per backend (see `_cloud_field` for the pattern), strict
   for anything that is not Windows.
2. Entries in `WAZUH_GROUPS`, `WAZUH_IF_GROUP`, `SENTINEL_TABLES` and
   `SPLUNK_SOURCETYPES`.
3. A test in `tools/test_sigma_compile.py` that proves a field lands in the
   right namespace and **not** in `win.eventdata.*`.
4. At least one rule using it, with a `validation.fire` that works.

Open issues labelled `log source` have a worked plan for each one we want.

## Adding a Sigma modifier

`to_regex`, `_splunk_value` and `_kql_value` are the three places a value is
rendered. A modifier that any backend cannot express faithfully must raise
`Unsupported` on that backend rather than approximate. Add a test for each
backend showing the rendered form, and run the SigmaHQ report before and after:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
python tools/sigma_compile.py --input /tmp/sigma/rules --backend report
```

The translated count should go up and nothing that previously translated
should change meaning. CI checks the first part; you check the second.

## Pull requests

- One rule or one compiler change per PR. Reviewing a detection is slow work
  and bundling makes it slower.
- CI runs the linter, the tests, compiles every backend, and parses the Wazuh
  XML. Green CI is the bar for merge; a reviewer who runs Wazuh is the bar for
  `stable`.
