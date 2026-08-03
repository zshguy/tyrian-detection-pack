# Rules with no Sentinel output

These compile for Wazuh and Splunk but are deliberately not emitted as
KQL, because auditd arrives in Sentinel as unparsed `Syslog` text unless
you have built a custom table and DCR for it. A substring match on
`SyslogMessage` is not the same detection as a field match, so the
compiler declines rather than shipping something subtly weaker.

- `rules/credential-access/linux-shadow-file-access.yml` (auditd has no faithful Sentinel field mapping)
- `rules/defense-evasion/linux-auditd-tampering.yml` (auditd has no faithful Sentinel field mapping)
- `rules/defense-evasion/linux-execution-from-world-writable.yml` (auditd has no faithful Sentinel field mapping)
- `rules/defense-evasion/linux-log-deletion.yml` (auditd has no faithful Sentinel field mapping)
- `rules/discovery/linux-host-enumeration-burst.yml` (auditd has no faithful Sentinel field mapping)
- `rules/execution/linux-download-pipe-to-shell.yml` (auditd has no faithful Sentinel field mapping)
- `rules/execution/linux-reverse-shell.yml` (auditd has no faithful Sentinel field mapping)
- `rules/persistence/linux-account-manipulation.yml` (auditd has no faithful Sentinel field mapping)
- `rules/persistence/linux-cron-persistence.yml` (auditd has no faithful Sentinel field mapping)
- `rules/persistence/linux-kernel-module-load.yml` (auditd has no faithful Sentinel field mapping)
- `rules/persistence/linux-ld-preload-hijack.yml` (auditd has no faithful Sentinel field mapping)
- `rules/persistence/linux-ssh-authorized-keys-write.yml` (auditd has no faithful Sentinel field mapping)
- `rules/persistence/linux-systemd-service-persistence.yml` (auditd has no faithful Sentinel field mapping)
- `rules/privilege-escalation/linux-container-escape.yml` (auditd has no faithful Sentinel field mapping)
- `rules/privilege-escalation/linux-sudoers-modification.yml` (auditd has no faithful Sentinel field mapping)
