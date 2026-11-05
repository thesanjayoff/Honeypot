"""``honeynet`` command line: run services, the analyser and the dashboard, plus local test-mode helpers.

    honeynet run ssh http ...        honeypot service(s) (what each container runs)
    honeynet analyze [--once]        static-analysis worker over the quarantine
    honeynet dashboard               private dashboard (needs HONEYNET_DASHBOARD_PASSWORD_HASH)
    honeynet fetcher                 sandboxed downloader (optional)
    honeynet hash-password           make a dashboard password hash
    honeynet export ...              blocklists / IOC feeds / daily report from the database
    honeynet demo                    dashboard filled with synthetic traffic (no services, test mode)
    honeynet dev                     everything on loopback with a live attack simulator (test mode)
"""

from __future__ import annotations

import argparse
import getpass
import logging
import sys
import threading
import time
from pathlib import Path

from . import __version__
from .common.config import Settings, load_settings


def _logging(verbose: bool = False) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)


def _test_settings(args: argparse.Namespace) -> Settings:
    """Local test mode: loopback only, simulated geo, no password needed, data in a throwaway directory."""
    s = load_settings()
    s.test_mode = True
    s.data_dir = Path(args.data_dir).resolve()
    s.bind_host = "127.0.0.1"
    s.dashboard_host = "127.0.0.1"
    s.dashboard_port = args.port
    s.fetcher_url = ""
    s.abuseipdb_enabled = False
    s.bazaar_enabled = False
    s.webhook_url = ""
    s.smtp_host = ""
    if getattr(args, "password", None):
        s.dashboard_password = args.password
    return s


# ---------------------------------------------------------------------------- simple commands
def cmd_run(args: argparse.Namespace) -> int:
    from .runner import main as runner_main

    runner_main(args.services + (["-v"] if args.verbose else []))
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    from .analysis.worker import AnalysisWorker

    _logging(args.verbose)
    w = AnalysisWorker(load_settings())
    if args.once:
        print(f"analysed {w.run_once()} sample(s)")
    else:
        w.run_forever()
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    from .dashboard.app import serve

    _logging(args.verbose)
    s = load_settings()
    if args.host:
        s.dashboard_host = args.host
    if args.port:
        s.dashboard_port = args.port
    serve(s)
    return 0


def cmd_fetcher(args: argparse.Namespace) -> int:
    from .fetcher import main as fetcher_main

    fetcher_main()
    return 0


def cmd_hash_password(args: argparse.Namespace) -> int:
    from .dashboard.auth import hash_password

    pw = args.password or getpass.getpass("Dashboard password: ")
    if not args.password and getpass.getpass("Repeat: ") != pw:
        print("passwords differ", file=sys.stderr)
        return 1
    if len(pw) < 12:
        print("warning: use at least 12 characters (the dashboard may face the internet through your tunnel)", file=sys.stderr)
    print(hash_password(pw))
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from .dashboard import exports, report
    from .dashboard.db import DB

    s = load_settings()
    db = DB(s.db_path)
    if args.what == "blocklist":
        entries = exports.blocklist_entries(db, s, days=args.days, level=args.level, min_score=0)
        out = exports.render_blocklist(entries, args.fmt, level=args.level, days=args.days)
    elif args.what == "iocs":
        out = exports.render_iocs(exports.ioc_rows(db, s, include_private=False, min_confidence=args.min_confidence), args.fmt if args.fmt in ("json", "csv") else "json")
    elif args.what == "c2":
        out = exports.render_c2(exports.c2_indicators(db, s), args.kind)
    else:
        since, until = time.time() - args.days * 86400, time.time()
        rep = report.build(db, s, since, until)
        out = report.render_html(rep, s) if args.fmt == "html" else report.render_markdown(rep, s)
    sys.stdout.write(s.redactor().scrub(out))
    return 0


# ---------------------------------------------------------------------------- local test modes
def _start_analysis_thread(s: Settings) -> threading.Event:
    from .analysis.worker import AnalysisWorker

    stop = threading.Event()
    s.analysis_poll_seconds = 2
    threading.Thread(target=AnalysisWorker(s).run_forever, args=(stop,), name="analysis", daemon=True).start()
    return stop


def cmd_demo(args: argparse.Namespace) -> int:
    from .dashboard.app import serve
    from .simulator.synthetic import SyntheticTraffic

    _logging(args.verbose)
    s = _test_settings(args)
    s.data_dir.mkdir(parents=True, exist_ok=True)
    syn = SyntheticTraffic(s, seed=args.seed)
    n = syn.backfill(hours=args.hours, per_hour=args.per_hour)
    print(f"wrote {n} synthetic sessions into {s.data_dir} (documentation-range IPs, simulated geo, harmless samples)")
    _start_analysis_thread(s)
    if args.live:
        threading.Thread(target=syn.live, args=(10**9, args.live), name="synthetic-live", daemon=True).start()
    print(f"dashboard: http://127.0.0.1:{s.dashboard_port}/   (test mode: no password)" if not s.dashboard_password
          else f"dashboard: http://127.0.0.1:{s.dashboard_port}/   (password from --password)")
    serve(s)
    return 0


def cmd_dev(args: argparse.Namespace) -> int:
    from .dashboard.app import serve
    from .simulator.live import run_dev_stack

    _logging(args.verbose)
    s = _test_settings(args)
    s.data_dir.mkdir(parents=True, exist_ok=True)
    def ready() -> None:
        print(f"dashboard: http://127.0.0.1:{s.dashboard_port}/   ({'password required' if s.dashboard_password else 'test mode: no password'})  - Ctrl+C to stop")
        serve(s)

    run_dev_stack(s, rate_per_min=args.rate, attacks=not args.no_attacks, backfill_hours=args.backfill, on_ready=ready)
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    import asyncio

    from .simulator.live import LiveAttacker

    _logging(args.verbose)
    s = load_settings()
    s.test_mode = True
    atk = LiveAttacker(args.host, s.ports, seed=args.seed)
    asyncio.run(atk.run(duration=args.seconds, rate_per_min=args.rate))
    return 0


# ---------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="honeynet", description="personal honeypot network + attack dashboard")
    ap.add_argument("--version", action="version", version=f"honeynet {__version__}")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("run", help="run honeypot service(s)")
    p.add_argument("services", nargs="+")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("analyze", help="static analysis worker")
    p.add_argument("--once", action="store_true")
    p.set_defaults(fn=cmd_analyze)

    p = sub.add_parser("dashboard", help="serve the dashboard")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.set_defaults(fn=cmd_dashboard)

    sub.add_parser("fetcher", help="sandboxed downloader").set_defaults(fn=cmd_fetcher)

    p = sub.add_parser("hash-password", help="hash a dashboard password")
    p.add_argument("--password", help="(avoid: ends up in shell history)")
    p.set_defaults(fn=cmd_hash_password)

    p = sub.add_parser("export", help="export from the database")
    p.add_argument("what", choices=["blocklist", "iocs", "c2", "report"])
    p.add_argument("--fmt", default="txt", help="blocklist: txt|csv|json|ipset|iptables|nft|ufw|pf; iocs: json|csv; report: md|html")
    p.add_argument("--level", default="suspicious", choices=["malicious", "suspicious", "all"])
    p.add_argument("--days", type=float, default=30)
    p.add_argument("--min-confidence", type=float, default=0.4)
    p.add_argument("--kind", default="ips", choices=["ips", "domains", "urls"])
    p.set_defaults(fn=cmd_export)

    def test_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--data-dir", default=".devdata")
        p.add_argument("--port", type=int, default=8088, help="dashboard port (loopback only)")
        p.add_argument("--password", help="require this dashboard password even in test mode")

    p = sub.add_parser("demo", help="dashboard with synthetic data (test mode)")
    test_args(p)
    p.add_argument("--hours", type=float, default=36)
    p.add_argument("--per-hour", type=int, default=70)
    p.add_argument("--live", type=float, default=15, help="new synthetic sessions per minute while running (0 = none)")
    p.add_argument("--seed", type=int, default=1337)
    p.set_defaults(fn=cmd_demo)

    p = sub.add_parser("dev", help="honeypots + analyser + dashboard + live attack simulator on loopback (test mode)")
    test_args(p)
    p.add_argument("--rate", type=float, default=30, help="simulated attacks per minute")
    p.add_argument("--no-attacks", action="store_true", help="start the stack without the simulator")
    p.add_argument("--backfill", type=float, default=24, help="hours of synthetic history to pre-load (0 = none)")
    p.set_defaults(fn=cmd_dev)

    p = sub.add_parser("simulate", help="run the live attack simulator against running honeypots (test mode, loopback only)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--seconds", type=float, default=60)
    p.add_argument("--rate", type=float, default=30)
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(fn=cmd_simulate)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args) or 0)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
