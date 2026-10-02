"""Tests for the Sigma compiler.

Every case here is a translation that was wrong at some point, or is easy to get
wrong in a way that produces a rule which deploys cleanly and never fires. That
failure mode is silent in production, so it has to be loud here.

    python -m unittest discover -s tools -p "test_*.py" -v
"""
import pathlib
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import sigma_compile as sc  # noqa: E402


def rule(**over):
    """A minimal rule that passes strict validation, for overriding per test."""
    base = {
        "title": "Test rule",
        "id": "00000000-0000-0000-0000-000000000000",
        "description": "test",
        "status": "experimental",
        "level": "high",
        "tags": ["attack.t1059"],
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection": {"selection": {"Image|endswith": "\\evil.exe"}, "condition": "selection"},
        "validation": {"atomic": "T1059", "fire": "evil.exe"},
        "_path": "rules/test/test.yml",
        "_tactic": "execution",
    }
    base.update(over)
    return base


class UnfieldedKeywords(unittest.TestCase):
    """Sigma keyword search means the value appears somewhere in the event."""

    KEYWORDS = rule(detection={"keywords": ["SuspiciousOperation", "DisallowedHost"],
                               "condition": "keywords"})

    def test_compiles_to_regex_not_field(self):
        xml = sc.render_wazuh([dict(self.KEYWORDS)])
        self.assertIn("<regex", xml)
        self.assertNotIn('<field name=""', xml)

    def test_is_not_anchored(self):
        # `^SuspiciousOperation$` against a whole log line can never match.
        # This is the bug the anchoring rules exist to prevent.
        xml = sc.render_wazuh([dict(self.KEYWORDS)])
        self.assertNotIn("^SuspiciousOperation$", xml)
        self.assertIn("SuspiciousOperation|DisallowedHost", xml)

    def test_bare_pipe_all_key_is_a_keyword(self):
        # `'|all':` with nothing before the pipe is an unfielded keyword list,
        # not a field named "". It used to raise IndexError.
        r = rule(detection={"kw": {"|all": ["FileNotFoundException", "/../../.."]},
                            "condition": "kw"})
        xml = sc.render_wazuh([r])
        self.assertIn("(?=.*FileNotFoundException)", xml)

    def test_splunk_emits_a_bare_term(self):
        spl = sc.render_splunk([dict(self.KEYWORDS)])
        self.assertIn('"*SuspiciousOperation*"', spl)
        self.assertNotIn('="*SuspiciousOperation*"', spl)

    def test_sentinel_declines_rather_than_degrading(self):
        # KQL can only express this as a table-wide `search`, so it is declined.
        _files, declined = sc.render_sentinel([dict(self.KEYWORDS)])
        self.assertEqual(len(declined), 1)
        self.assertIn("unfielded keyword", declined[0][1])


class Disjunctions(unittest.TestCase):
    """A Wazuh rule is one flat conjunction, so an `or` has to become siblings."""

    def test_or_becomes_two_rules_not_one_anded_rule(self):
        r = rule(detection={
            "vss": {"Image|endswith": "\\vssadmin.exe"},
            "wmic": {"Image|endswith": "\\wmic.exe"},
            "condition": "vss or wmic",
        })
        xml = sc.render_wazuh([r])
        self.assertEqual(xml.count("<rule id="), 2)
        # The original bug ANDed them, which required one Image to be two
        # different executables at once.
        for block in xml.split("<rule id=")[1:]:
            self.assertEqual(block.count('<field name="win.eventdata.image"'), 1)

    def test_runaway_expansion_is_refused(self):
        det = {f"s{i}": {"Image": f"x{i}.exe"} for i in range(sc.MAX_WAZUH_VARIANTS + 2)}
        det["condition"] = " or ".join(k for k in det)
        with self.assertRaises(sc.Unsupported):
            sc.render_wazuh([rule(detection=det)])


class AllModifier(unittest.TestCase):
    def test_all_uses_lookaheads_not_alternation(self):
        # Alternation means "any". `|all` means all of them.
        r = rule(detection={"sel": {"CommandLine|contains|all": ["-enc", "-w hidden"]},
                            "condition": "sel"})
        xml = sc.render_wazuh([r])
        self.assertIn("(?=.*", xml)
        self.assertIn('type="pcre2"', xml)
        self.assertNotIn("\\-enc|", xml)


class WellFormedXml(unittest.TestCase):
    """Wazuh rejects the entire ruleset on one parse error, so this is fatal."""

    def test_bundled_corpus_parses(self):
        xml = sc.render_wazuh(sc.load_rules())
        ET.fromstring(f"<root>{xml}</root>")

    def test_double_hyphen_in_a_title_cannot_break_the_file(self):
        xml = sc.render_wazuh([rule(title="Living--off--the--land")])
        ET.fromstring(f"<root>{xml}</root>")

    def test_validation_command_survives_verbatim(self):
        # Attack commands are full of `--`, which is illegal in an XML comment,
        # so they are carried as <info> element text instead of being mangled.
        xml = sc.render_wazuh([rule(validation={"atomic": "T1059", "fire": "rubeus.exe --stats"})])
        self.assertIn("--stats", xml)
        ET.fromstring(f"<root>{xml}</root>")


class LinuxFieldStrictness(unittest.TestCase):
    """auditd has no CommandLine. Mapping one anyway produces a dead rule."""

    def test_commandline_on_linux_is_refused_with_the_reason(self):
        with self.assertRaises(sc.Unsupported) as ctx:
            sc.resolve_field("wazuh", "linux", "CommandLine")
        self.assertIn("not an auditd field", str(ctx.exception))
        self.assertIn("EXECVE", str(ctx.exception))

    def test_raw_auditd_names_resolve(self):
        self.assertEqual(sc.resolve_field("wazuh", "linux", "a0"), "audit.execve.a0")
        self.assertEqual(sc.resolve_field("wazuh", "linux", "exe"), "audit.exe")
        self.assertEqual(sc.resolve_field("wazuh", "linux", "key"), "audit.key")

    def test_lookup_is_case_insensitive(self):
        # Sigma auditd rules say `type`; the field table says `Type`.
        self.assertEqual(sc.resolve_field("wazuh", "linux", "type"),
                         sc.resolve_field("wazuh", "linux", "Type"))

    def test_windows_falls_back_to_a_derived_sysmon_name(self):
        self.assertEqual(sc.resolve_field("wazuh", "windows", "SomeNewField"),
                         "win.eventdata.someNewField")


class LogsourceScoping(unittest.TestCase):
    def test_windows_without_a_service_keeps_its_scope(self):
        xml = sc.render_wazuh([rule(logsource={"product": "windows",
                                               "category": "process_creation"})])
        self.assertIn("<if_group>windows</if_group>", xml)

    def test_unknown_product_is_not_silently_scoped_to_windows(self):
        # A Django rule scoped to Windows events is a rule that never fires.
        xml = sc.render_wazuh([rule(logsource={"product": "django", "category": "application"})])
        body = xml.split("<group ", 1)[1]        # the TUNE comment names the element
        self.assertNotIn("<if_group>", body)
        self.assertIn("TUNE:", xml)


class Aggregation(unittest.TestCase):
    AGG = rule(detection={
        "selection": {"EventID": 4625},
        "condition": "selection | count(TargetUserName) by IpAddress > 10",
        "timeframe": "5m",
    }, logsource={"product": "windows", "service": "security"})

    def test_wazuh_frequency_and_timeframe(self):
        xml = sc.render_wazuh([dict(self.AGG)])
        self.assertIn("<frequency>10</frequency>", xml)
        self.assertIn("<timeframe>300</timeframe>", xml)

    def test_splunk_counts_distinct(self):
        self.assertIn("dc(TargetUserName)", sc.render_splunk([dict(self.AGG)]))

    def test_sentinel_bins_by_the_timeframe(self):
        files, _ = sc.render_sentinel([dict(self.AGG)])
        self.assertIn("bin(TimeGenerated, 5m)", files[0][1])


class ForeignCorpora(unittest.TestCase):
    """Somebody elses rules are screened per rule, not all-or-nothing."""

    def test_lax_mode_fills_defaults_instead_of_refusing(self):
        r = {"title": "no level, no tags", "logsource": {"product": "windows"},
             "detection": {"sel": {"Image": "x.exe"}, "condition": "sel"},
             "_path": "x.yml", "_tactic": "uncategorised"}
        notes = sc.relax(r)
        self.assertEqual(r["level"], "medium")
        self.assertTrue(any("medium" in n for n in notes))
        self.assertEqual(sc.validate(r, strict=False), [])

    def test_strict_mode_still_demands_the_house_standard(self):
        r = {"title": "no evidence block", "logsource": {"product": "windows"},
             "level": "high", "tags": ["attack.t1059"],
             "detection": {"sel": {"Image": "x.exe"}, "condition": "sel"},
             "_path": "x.yml", "_tactic": "uncategorised"}
        self.assertTrue(any("validation" in e for e in sc.validate(r, strict=True)))

    def test_a_rule_that_cannot_translate_is_skipped_not_fatal(self):
        good = rule()
        bad = rule(title="bad", detection={"sel": {"CommandLine": "x"}, "condition": "sel"},
                   logsource={"product": "linux", "service": "auditd"})
        ok, declined = sc.screen([good, bad], "wazuh", strict=False)
        self.assertEqual([r["title"] for r in ok], ["Test rule"])
        self.assertEqual(len(declined), 1)

    def test_condition_lists_are_named_rather_than_stringified(self):
        r = rule(detection={"a": {"Image": "x.exe"}, "condition": ["a", "a"]})
        self.assertTrue(any("list" in e for e in sc.validate(r, strict=False)))

    def test_tactic_comes_from_tags_when_the_directory_does_not_say(self):
        doc = {"tags": ["attack.credential_access", "attack.t1003"]}
        self.assertEqual(sc.tactic_of(doc, pathlib.Path("rules/windows/builtin/x.yml")),
                         "credential-access")


class SigmaEscapes(unittest.TestCase):
    """`\\` in a Sigma value is ONE literal backslash. Rendering it as two made
    every rule written that way demand `\\powershell.exe` in the event."""

    def _rule(self, value, mod="endswith"):
        return rule(detection={"selection": {f"Image|{mod}": value}, "condition": "selection"})

    def test_escaped_and_bare_backslash_compile_identically(self):
        a = sc.render_wazuh([self._rule("\\\\evil.exe")])
        b = sc.render_wazuh([self._rule("\\evil.exe")])
        self.assertEqual(a, b)
        self.assertIn(r"(?i)\\evil\.exe$</field>", a)

    def test_escaped_wildcard_is_literal(self):
        self.assertEqual(sc.wildcard_to_regex("a\\*b*"), r"a\*b.*")

    def test_splunk_escapes_the_backslash_once(self):
        spl = sc.render_splunk([self._rule("\\\\evil.exe")])
        self.assertIn(r'Image="*\\evil.exe"', spl)


class CaseInsensitivity(unittest.TestCase):
    """Sigma matches case-insensitively unless |cased; Wazuh PCRE2 does not."""

    def test_wazuh_patterns_are_case_insensitive(self):
        xml = sc.render_wazuh([rule()])
        self.assertIn('type="pcre2">(?i)', xml)

    def test_cased_and_re_stay_case_sensitive(self):
        for mod in ("endswith|cased", "re"):
            r = rule(detection={"selection": {f"Image|{mod}": "evil"}, "condition": "selection"})
            self.assertNotIn("(?i)", sc.render_wazuh([r]))


class SentinelLiterals(unittest.TestCase):
    def _kql(self, det):
        files, _ = sc.render_sentinel([rule(detection=det)])
        return files[0][1]

    def test_backslashes_use_verbatim_strings(self):
        # A regular KQL string "\evil.exe" is a syntax error.
        kql = self._kql({"selection": {"Image|endswith": "\\evil.exe"}, "condition": "selection"})
        self.assertIn('endswith @"\\evil.exe"', kql)

    def test_contains_is_substring_not_term_match(self):
        # has_any matches whole terms, so ' -enc' would miss '-EncodedCommand'.
        kql = self._kql({"selection": {"CommandLine|contains": [" -enc", " -e ", " -ec "]},
                         "condition": "selection"})
        self.assertNotIn("has_any", kql)
        self.assertIn('contains @" -enc"', kql)

    def test_wildcard_inside_contains_becomes_a_regex(self):
        kql = self._kql({"selection": {"CommandLine|contains": "a*b"}, "condition": "selection"})
        self.assertIn('matches regex @"(?i)a.*b"', kql)


class CloudLogsources(unittest.TestCase):
    """Cloud fields must land in each connector's namespace, never win.eventdata."""

    def _rule(self, product, service, sel, cond="selection"):
        return rule(logsource={"product": product, "service": service},
                    detection={"selection": sel, "condition": cond})

    def test_aws_fields_per_backend(self):
        r = self._rule("aws", "cloudtrail", {"eventName": "StopLogging",
                                             "requestParameters.policyArn": "x"})
        xml = sc.render_wazuh([r])
        self.assertIn('name="aws.eventName"', xml)
        self.assertIn("<if_group>amazon</if_group>", xml)
        self.assertNotIn("win.eventdata", xml)
        self.assertIn('sourcetype="aws:cloudtrail"', sc.render_splunk([r]))
        kql = sc.render_sentinel([r])[0][0][1]
        self.assertIn("AWSCloudTrail", kql)
        self.assertIn('EventName =~ @"StopLogging"', kql)
        self.assertIn("tostring(parse_json(RequestParameters).policyArn)", kql)

    def test_entra_signin_table_and_splunk_envelope(self):
        r = self._rule("azure", "signinlogs", {"ResultType": "50126"},
                       "selection | count(UserPrincipalName) by IPAddress >= 10")
        self.assertIn("SigninLogs", sc.render_sentinel([r])[0][0][1])
        spl = sc.render_splunk([r])
        self.assertIn('resultType="50126"', spl)
        self.assertIn("dc(properties.userPrincipalName)", spl)

    def test_m365_uses_office365_namespace(self):
        r = self._rule("m365", "exchange", {"Operation": "New-InboxRule"})
        self.assertIn('name="office365.Operation"', sc.render_wazuh([r]))
        self.assertIn("OfficeActivity", sc.render_sentinel([r])[0][0][1])

    def test_wazuh_distinct_count_uses_different_field(self):
        r = self._rule("azure", "signinlogs", {"ResultType": "50126"},
                       "selection | count(UserPrincipalName) by IPAddress >= 10")
        xml = sc.render_wazuh([r])
        self.assertIn("<same_field>IPAddress</same_field>", xml)
        self.assertIn("<different_field>UserPrincipalName</different_field>", xml)


class Modifiers(unittest.TestCase):
    """A modifier the compiler does not understand must refuse the rule, never
    be dropped: `|cidr: 10.0.0.0/8` as a literal is a rule that never fires."""

    def _r(self, sel):
        return rule(detection={"selection": sel, "condition": "selection"})

    def _all(self, sel):
        r = self._r(sel)
        return (sc.render_wazuh([r]), sc.render_splunk([r]), sc.render_sentinel([r])[0][0][1])

    def test_unknown_modifier_is_refused_everywhere(self):
        for sel in ({"X|fieldref": "Y"}, {"X|exists": True}, {"X|gt": 5}, {"X|contains|bogus": "a"}):
            for render in (sc.render_wazuh, sc.render_splunk, sc.render_sentinel):
                with self.assertRaises(sc.Unsupported, msg=f"{render.__name__} {sel}"):
                    render([self._r(sel)])
            self.assertTrue(any("modifier" in e for e in sc.validate(self._r(sel))))

    def test_windash(self):
        xml, spl, kql = self._all({"CommandLine|windash|contains": " -enc"})
        self.assertIn(r"\ [-/–—―]enc", xml)
        self.assertIn('CommandLine="* /enc*"', spl)
        self.assertIn('CommandLine="* -enc*"', spl)
        self.assertIn(r'matches regex @"(?i)\ [-/–—―]enc"', kql)

    def test_cidr(self):
        xml, spl, kql = self._all({"DestinationIp|cidr": "192.168.0.0/16"})
        self.assertIn(r"^192\.168\.", xml)
        self.assertIn('DestinationIp="192.168.0.0/16"', spl)
        self.assertIn('ipv4_is_in_range(DestinationIp, @"192.168.0.0/16")', kql)

    def test_cidr_wazuh_refuses_what_a_regex_cannot_say(self):
        for bad in ("10.0.0.0/12", "fe80::/10"):
            with self.assertRaises(sc.Unsupported):
                sc.render_wazuh([self._r({"DestinationIp|cidr": bad})])
        # ...but the backends with a native primitive still take them.
        kql = sc.render_sentinel([self._r({"DestinationIp|cidr": "fe80::/10"})])[0][0][1]
        self.assertIn("ipv6_is_in_range", kql)

    def test_base64offset_matches_pysigma(self):
        vals, mods = sc.expand_values(["/bin/bash"], ["base64offset", "contains"])
        self.assertEqual(vals, ["L2Jpbi9iYXNo", "9iaW4vYmFza", "vYmluL2Jhc2"])
        self.assertIn("cased", mods)          # base64 is case-sensitive
        xml = sc.render_wazuh([self._r({"CommandLine|base64offset|contains": "/bin/bash"})])
        self.assertNotIn("(?i)", xml)

    def test_utf16le_base64offset(self):
        vals, _ = sc.expand_values(["Invoke"], ["utf16le", "base64offset", "contains"])
        self.assertEqual(vals[0], "SQBuAHYAbwBrAGUA")

    def test_re_flags(self):
        xml, spl, kql = self._all({"Image|re|i": r"evil\.exe$"})
        self.assertIn(r"(?i)evil\.exe$", xml)
        self.assertIn(r'match(Image, "(?i)evil\\.exe$")', spl)
        self.assertIn(r'matches regex @"(?i)evil\.exe$"', kql)



class MoreLogsources(unittest.TestCase):
    def _rule(self, product, service, sel, cond="selection"):
        return rule(logsource={"product": product, "service": service},
                    detection={"selection": sel, "condition": cond})

    def test_okta_github_gcp_land_in_their_own_namespaces(self):
        cases = [
            ("okta", "okta", {"eventType": "user.mfa.factor.reset_all"},
             "eventType", 'sourcetype="OktaIM2:log"', "OktaSSO"),
            ("github", "audit", {"action": "org.update_member"},
             'name="github.action"', 'sourcetype="github:audit"', 'action_s =~'),
            ("gcp", "gcp.audit", {"gcp.audit.method_name": "x"},
             'name="gcp.protoPayload.methodName"', "data.protoPayload.methodName", "MethodName =~"),
        ]
        for product, service, sel, wz, spl, kql in cases:
            r = self._rule(product, service, sel)
            xml = sc.render_wazuh([r])
            self.assertIn(wz, xml, product)
            self.assertNotIn("win.eventdata", xml, product)
            self.assertIn(spl, sc.render_splunk([r]), product)
            self.assertIn(kql, sc.render_sentinel([r])[0][0][1], product)

    def test_okta_has_no_if_group_because_json_is_a_decoder_not_a_group(self):
        xml = sc.render_wazuh([self._rule("okta", "okta", {"eventType": "x"})])
        self.assertNotIn("<if_group>", xml)

    def test_macos_process_and_file_tables(self):
        proc = rule(logsource={"product": "macos", "category": "process_creation"},
                    detection={"selection": {"Image|endswith": "/osascript"}, "condition": "selection"})
        self.assertIn('name="osquery.columns.path"', sc.render_wazuh([proc]))
        self.assertIn("DeviceProcessEvents", sc.render_sentinel([proc])[0][0][1])
        fe = rule(logsource={"product": "macos", "category": "file_event"},
                  detection={"selection": {"TargetFilename|endswith": ".plist"}, "condition": "selection"})
        self.assertIn('name="file_events"', sc.render_splunk([fe]))
        self.assertIn("DeviceFileEvents", sc.render_sentinel([fe])[0][0][1])

    def test_macos_parent_image_refused_on_osquery_but_fine_on_sentinel(self):
        r = rule(logsource={"product": "macos", "category": "process_creation"},
                 detection={"selection": {"ParentImage|endswith": "/bash"}, "condition": "selection"})
        with self.assertRaises(sc.Unsupported):
            sc.render_wazuh([r])
        self.assertIn("InitiatingProcessFolderPath", sc.render_sentinel([r])[0][0][1])


class BundledCorpus(unittest.TestCase):
    def test_every_shipped_rule_meets_the_house_standard(self):
        problems = {r["_path"]: sc.validate(r) for r in sc.load_rules()}
        self.assertEqual({k: v for k, v in problems.items() if v}, {})

    def test_every_shipped_rule_carries_a_way_to_trigger_it(self):
        for r in sc.load_rules():
            with self.subTest(rule=r["_path"]):
                self.assertTrue(str(r["validation"]["fire"]).strip())


if __name__ == "__main__":
    unittest.main(verbosity=2)
