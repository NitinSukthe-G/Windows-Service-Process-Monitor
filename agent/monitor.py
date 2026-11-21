"""Windows Service & Process Monitoring Agent - command-line entry point.

Examples
    python agent/monitor.py                      single full scan, writes reports/
    python agent/monitor.py --watch              continuous monitoring
    python agent/monitor.py --demo               safe synthetic attack scenario -> reports/demo/
    python agent/monitor.py --view tree          print the process tree
    python agent/monitor.py --update-baseline    accept the current services/startup as normal
    python agent/monitor.py --list-rules         show the detection catalog
"""

import argparse
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent import config  # noqa: E402
from agent.baseline import build_baseline, load_baseline, save_baseline  # noqa: E402
from agent.engine import attach_enrichment, build_summary, collect_paths, run_detection  # noqa: E402
from agent.reporting import Redactor, append_history, write_reports  # noqa: E402
from agent.rules_data import RULE_CATALOG, SEVERITY_RANK  # noqa: E402

log = logging.getLogger("monitor")

COLORS = {"CRITICAL": "\033[1;37;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[33m", "LOW": "\033[32m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
USE_COLOR = sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))


def paint(text, code):
    return f"{code}{text}{RESET}" if USE_COLOR else text


def setup_logging(verbose=False):
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    logfile = config.LOG_DIR / f"monitor-{datetime.now():%Y-%m-%d}.log"
    handlers = [logging.FileHandler(logfile, encoding="utf-8")]
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=handlers, force=True,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    return logfile


def enable_ansi():
    global USE_COLOR
    if os.name == "nt":
        os.system("")  # enables VT sequences in modern Windows terminals
    USE_COLOR = USE_COLOR and os.environ.get("NO_COLOR") is None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class Scanner:
    def __init__(self, args):
        self.args = args
        self.custom = config.load_custom_rules()
        self.ioc = config.load_ioc_hashes()
        self.redactor = Redactor(enabled=not args.no_redact)
        self.enricher = None
        self.deep = {}              # cached services/startup/tasks between watch cycles
        self.known_alerts = set()

    def _enricher(self):
        if self.enricher is None:
            from agent.enrichment import Enricher
            self.enricher = Enricher(check_signatures=not self.args.no_signatures)
        return self.enricher

    def scan(self, deep=True):
        from agent import collectors

        started = time.time()
        snapshot = {"processes": collectors.collect_processes()}
        if deep or not self.deep:
            # The slow collectors are PowerShell subprocesses, so threads give a real speed-up.
            def services_and_acls():
                services = collectors.collect_services()
                acl = {} if self.args.quick else collectors.check_service_acls(services)
                return services, acl

            with ThreadPoolExecutor(max_workers=3) as pool:
                f_services = pool.submit(services_and_acls)
                f_tasks = pool.submit(lambda: [] if self.args.no_tasks else collectors.collect_scheduled_tasks())
                f_startup = pool.submit(collectors.collect_startup_entries)
                snapshot["services"], snapshot["service_acl"] = f_services.result()
                snapshot["tasks"] = f_tasks.result()
                snapshot["startup"] = f_startup.result()
            self.deep = {k: snapshot[k] for k in ("services", "startup", "tasks", "service_acl")}
        else:
            snapshot.update(self.deep)

        enrichment = self._enricher().enrich(collect_paths(snapshot))
        attach_enrichment(snapshot, enrichment)

        baseline = load_baseline()
        status = "loaded"
        if baseline is None:
            baseline = build_baseline(snapshot)
            save_baseline(baseline)
            status = "initialised (first run - drift rules start next scan)"
            baseline_for_rules = None
        else:
            baseline_for_rules = baseline
        alerts, suppressed = run_detection(snapshot, baseline_for_rules, self.custom, self.ioc)

        summary = build_summary(snapshot, alerts, mode="live", suppressed=suppressed,
                                duration=time.time() - started, is_admin=collectors.is_admin(),
                                baseline_status=status, signatures_checked=not self.args.no_signatures)
        return snapshot, alerts, summary

    def publish(self, snapshot, alerts, summary, out_dir):
        files = write_reports(out_dir, snapshot, alerts, summary, self.redactor)
        append_history(out_dir / "scan_history.jsonl", summary, self.redactor)
        for alert in alerts:
            if alert["severity"] in ("CRITICAL", "HIGH"):
                log.warning("ALERT [%s] %s %s | %s", alert["severity"], alert["rule_id"], alert.get("name"), alert["reason"])
            else:
                log.info("ALERT [%s] %s %s | %s", alert["severity"], alert["rule_id"], alert.get("name"), alert["reason"])
        return files


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

def print_banner(title):
    print("\n" + "=" * 100)
    print(paint(title, BOLD))
    print("=" * 100)


def print_summary(summary):
    print_banner("MONITORING SUMMARY")
    rows = [
        ("Timestamp", summary["timestamp"]), ("Mode", summary["mode"]),
        ("Elevated (admin)", "yes" if summary["is_admin"] else "no (some processes/ACLs not visible)"),
        ("Processes / services", f"{summary['processes_detected']} / {summary['services_detected']}"),
        ("Startup entries / tasks", f"{summary['startup_entries_detected']} / {summary['scheduled_tasks_detected']}"),
        ("Baseline", summary["baseline_status"]),
        ("Signatures verified", "yes" if summary["signatures_checked"] else "no"),
        ("Scan duration", f"{summary['scan_duration_seconds']}s"),
    ]
    for key, value in rows:
        print(f"  {key:<26}: {value}")
    print()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        print("  " + paint(f"{sev:<9}", COLORS[sev]) + f": {summary[sev.lower() + '_alerts']}")
    print(f"  {'TOTAL':<9}: {summary['total_alerts']}   (suppressed: {summary['suppressed_alerts']})")


def print_alerts(alerts, min_severity="LOW", limit=25):
    floor = SEVERITY_RANK[min_severity]
    shown = [a for a in alerts if SEVERITY_RANK[a["severity"]] >= floor]
    print_banner(f"TOP ALERTS ({min(limit, len(shown))} of {len(shown)} at >= {min_severity})")
    if not shown:
        print("  No alerts at this severity.")
        return
    for alert in shown[:limit]:
        pid = f" PID {alert['pid']}" if alert.get("pid") is not None else ""
        print(f"  {paint(' ' + alert['severity'] + ' ', COLORS[alert['severity']])} {alert['rule_id']}  "
              f"{paint(str(alert.get('name')), BOLD)}{pid}  {paint('[' + alert['mitre_id'] + ']', DIM) if alert['mitre_id'] != '-' else ''}")
        print(f"      {alert['reason']}")
        lineage = (alert.get("evidence") or {}).get("lineage")
        if lineage and alert["rule_id"].startswith("PROC"):
            print(paint(f"      chain: {lineage}", DIM))


def print_outputs(files):
    print_banner("REPORTS WRITTEN")
    for key, path in files.items():
        print(f"  {key:<16}: {os.path.relpath(path, config.PROJECT_ROOT)}")


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

def view_tree(processes):
    from agent.process_rules import ProcessIndex
    index = ProcessIndex(processes)
    roots = [p for p in processes if index.parent_of(p) is None]
    print_banner("PROCESS TREE")

    def walk(proc, prefix="", last=True, depth=0):
        branch = "" if depth == 0 else ("└─ " if last else "├─ ")
        print(f"{prefix}{branch}{proc.get('name')} ({proc['pid']})")
        kids = sorted(index.children.get(proc["pid"], []), key=lambda p: p["pid"])
        for i, kid in enumerate(kids):
            walk(kid, prefix + ("" if depth == 0 else ("   " if last else "│  ")), i == len(kids) - 1, depth + 1)

    for root in sorted(roots, key=lambda p: p["pid"]):
        walk(root)
    print(f"\n{len(processes)} processes")


def run_view(args):
    from agent import collectors
    if args.view in ("processes", "tree"):
        processes = collectors.collect_processes()
        if args.view == "tree":
            view_tree(processes)
        else:
            print_banner("WINDOWS PROCESSES")
            print(f"{'PID':<8}{'PPID':<8}{'NAME':<34}{'USER':<30}")
            for p in sorted(processes, key=lambda x: x["pid"]):
                print(f"{p['pid']:<8}{p['ppid']:<8}{str(p['name'])[:32]:<34}{str(p['username'] or '')[:28]:<30}")
            print(f"\n{len(processes)} processes")
    elif args.view == "services":
        services = collectors.collect_services()
        print_banner("WINDOWS SERVICES")
        print(f"{'NAME':<34}{'STATE':<10}{'START':<10}{'ACCOUNT':<28}")
        for s in services:
            print(f"{str(s['name'])[:32]:<34}{str(s['state']):<10}{str(s['start_mode']):<10}{str(s['start_name'] or '')[:26]:<28}")
        print(f"\n{len(services)} services")
    elif args.view == "startup":
        entries = collectors.collect_startup_entries()
        print_banner("STARTUP ENTRIES")
        for e in entries:
            print(f"{e['location']:<28}{e['name'][:30]:<32}{e['command'][:70]}")
        print(f"\n{len(entries)} entries")


def list_rules():
    print_banner(f"DETECTION RULES ({len(RULE_CATALOG)})")
    for rule_id, meta in RULE_CATALOG.items():
        print(f"  {rule_id:<9} {meta['name']:<52} {meta['technique']:<10} {meta['tactic']}")


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def run_demo(args):
    from agent.demo import build_demo
    from agent.engine import label_processes

    snapshot, baseline = build_demo()
    scanner = Scanner(args)
    label_processes(snapshot, scanner.custom)
    started = time.time()
    alerts, suppressed = run_detection(snapshot, baseline, {}, set())
    summary = build_summary(snapshot, alerts, mode="demo", suppressed=suppressed, duration=time.time() - started,
                            baseline_status="synthetic baseline", signatures_checked=True)
    files = scanner.publish(snapshot, alerts, summary, config.DEMO_REPORT_DIR)
    print_banner("DEMO MODE - synthetic attack scenarios (nothing is executed)")
    print_summary(summary)
    print_alerts(alerts, args.min_severity, args.top)
    print_outputs(files)
    return alerts


def run_once(args):
    print_banner("WINDOWS SERVICE & PROCESS MONITORING AGENT")
    if args.update_baseline:
        from agent import collectors
        snapshot = {"services": collectors.collect_services(), "startup": collectors.collect_startup_entries(),
                    "tasks": collectors.collect_scheduled_tasks()}
        path = save_baseline(build_baseline(snapshot))
        print(f"Baseline updated: {os.path.relpath(path, config.PROJECT_ROOT)} "
              f"({len(snapshot['services'])} services, {len(snapshot['startup'])} startup entries, {len(snapshot['tasks'])} tasks)")
        return []

    print("[1/4] Collecting processes, services, startup entries and scheduled tasks...")
    scanner = Scanner(args)
    if not args.no_signatures:
        print("[2/4] Verifying digital signatures (first run is slower; results are cached)...")
    snapshot, alerts, summary = scanner.scan(deep=True)
    print("[3/4] Applying detection rules, correlation and MITRE mapping...")
    files = scanner.publish(snapshot, alerts, summary, config.REPORT_DIR)
    print("[4/4] Reports written.")
    print_summary(summary)
    print_alerts(alerts, args.min_severity, args.top)
    print_outputs(files)
    return alerts


def run_watch(args):
    enable_ansi()
    scanner = Scanner(args)
    cycle, previous = 0, {}
    print_banner("CONTINUOUS MONITORING")
    print(f"Interval {args.interval}s | deep scan (services/startup/tasks) every {config.DEEP_SCAN_EVERY_N_CYCLES} cycles | CTRL+C to stop")
    try:
        while True:
            cycle += 1
            deep = (cycle - 1) % config.DEEP_SCAN_EVERY_N_CYCLES == 0
            snapshot, alerts, summary = scanner.scan(deep=deep)
            scanner.publish(snapshot, alerts, summary, config.REPORT_DIR)

            current = {(p["pid"], p.get("create_time")): p for p in snapshot["processes"]}
            new_procs = [p for key, p in current.items() if previous and key not in previous]
            previous = current
            fresh = [a for a in alerts if a["alert_id"] not in scanner.known_alerts]
            scanner.known_alerts.update(a["alert_id"] for a in alerts)

            stamp = datetime.now().strftime("%H:%M:%S")
            print(f"\n[{stamp}] cycle {cycle} ({'deep' if deep else 'fast'}) - {summary['processes_detected']} processes, "
                  f"{summary['total_alerts']} alerts "
                  f"(C{summary['critical_alerts']} H{summary['high_alerts']} M{summary['medium_alerts']} L{summary['low_alerts']}), "
                  f"{len(new_procs)} new process(es), {summary['scan_duration_seconds']}s")
            for proc in new_procs[:10]:
                log.info("NEW_PROCESS pid=%s ppid=%s name=%s path=%s", proc["pid"], proc["ppid"], proc["name"], proc["path"])
                print(f"   + {proc['name']} (PID {proc['pid']}, parent {proc['ppid']})")
            for alert in fresh[:10]:
                if SEVERITY_RANK[alert["severity"]] >= SEVERITY_RANK[args.min_severity]:
                    print("   ! " + paint(f" NEW {alert['severity']} ", COLORS[alert["severity"]]) +
                          f" {alert['rule_id']} {alert.get('name')} - {alert['reason']}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Windows Service & Process Monitoring Agent",
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("--watch", action="store_true", help="run continuously")
    parser.add_argument("--interval", type=int, default=config.DEFAULT_INTERVAL_SECONDS, help="seconds between watch scans")
    parser.add_argument("--demo", action="store_true", help="run the safe synthetic attack demo (reports/demo/)")
    parser.add_argument("--view", choices=["processes", "tree", "services", "startup"], help="print raw inventory and exit")
    parser.add_argument("--update-baseline", action="store_true", help="accept current services/startup/tasks as the new baseline")
    parser.add_argument("--list-rules", action="store_true", help="print the detection rule catalog")
    parser.add_argument("--no-signatures", action="store_true", help="skip Authenticode verification (faster)")
    parser.add_argument("--no-tasks", action="store_true", help="skip scheduled-task enumeration")
    parser.add_argument("--quick", action="store_true", help="skip the service ACL audit")
    parser.add_argument("--no-redact", action="store_true", help="keep real user/computer names in reports")
    parser.add_argument("--min-severity", default="MEDIUM", choices=list(SEVERITY_RANK), help="console severity floor")
    parser.add_argument("--top", type=int, default=25, help="alerts shown in the console")
    parser.add_argument("--fail-on", choices=list(SEVERITY_RANK), help="exit code 2 when an alert at/above this severity exists")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    enable_ansi()
    if args.list_rules:
        list_rules()
        return 0
    setup_logging(args.verbose)
    if os.name != "nt" and not args.demo:
        print("This agent collects Windows telemetry. Use --demo on other platforms.")
        return 1
    if args.view:
        run_view(args)
        return 0
    if args.watch:
        run_watch(args)
        return 0
    alerts = run_demo(args) if args.demo else run_once(args)
    if args.fail_on and any(SEVERITY_RANK[a["severity"]] >= SEVERITY_RANK[args.fail_on] for a in alerts):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
