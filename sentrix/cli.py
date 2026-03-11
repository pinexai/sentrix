"""sentrix CLI — command-line interface for red teaming, eval, monitoring, and more."""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from typing import Callable


def _load_fn(module_path: str) -> Callable:
    """Load a function from 'module:function' syntax."""
    if ":" not in module_path:
        print(f"[sentrix] Error: expected 'module:function' format, got '{module_path}'")
        sys.exit(1)
    module_name, fn_name = module_path.rsplit(":", 1)
    try:
        mod = importlib.import_module(module_name)
        return getattr(mod, fn_name)
    except (ImportError, AttributeError) as e:
        print(f"[sentrix] Error loading {module_path}: {e}")
        sys.exit(1)


def cmd_scan(args) -> None:
    """sentrix scan module:fn [--plugins ...] [--n 10] [--git-compare main] [--fail-on-regression]"""
    from sentrix import init, red_team
    init(persist=True)

    fn = _load_fn(args.target)
    plugins = [p.strip() for p in args.plugins.split(",")] if args.plugins else ["jailbreak", "pii", "harmful"]

    report = red_team(
        fn,
        plugins=plugins,
        n_attacks=args.n,
        git_compare=args.git_compare,
        fail_on_regression=args.fail_on_regression,
    )
    report.summary()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_json(), f, indent=2)
        print(f"[sentrix] Report saved to {args.output}")


def cmd_fingerprint(args) -> None:
    """sentrix fingerprint module:fn1 module:fn2 [--plugins all] [--n 10]"""
    from sentrix import init
    from sentrix.guard.fingerprint import fingerprint
    init(persist=True)

    targets = {}
    for t in args.targets:
        fn = _load_fn(t)
        targets[t] = fn

    plugins = [p.strip() for p in args.plugins.split(",")] if args.plugins else ["jailbreak", "pii", "harmful", "hallucination", "injection"]
    if args.plugins == "all":
        from sentrix.guard.attacks import PLUGIN_REGISTRY
        plugins = list(PLUGIN_REGISTRY.keys())

    fp = fingerprint(targets, plugins=plugins, n_attacks=args.n)
    fp.heatmap()


def cmd_auto_dataset(args) -> None:
    """sentrix auto-dataset module:fn [--n 20] [--focus adversarial] [--name myds]"""
    from sentrix import init, auto_dataset
    init(persist=True)

    fn = _load_fn(args.target)
    ds = auto_dataset(fn, n=args.n, focus=args.focus, name=args.name)
    print(f"[sentrix] Generated dataset '{ds.name}' with {len(ds)} items")


def cmd_scan_agent(args) -> None:
    from sentrix import init
    from sentrix.guard.agent import scan_agent
    init(persist=True)

    fn = _load_fn(args.target)
    report = scan_agent(fn, mcp_endpoint=args.mcp)
    report.summary()


def cmd_scan_rag(args) -> None:
    from sentrix import init
    from sentrix.guard.rag_scanner import scan_rag
    import os
    init(persist=True)

    # Load documents
    docs = []
    if os.path.isdir(args.docs):
        for f in os.listdir(args.docs):
            fp = os.path.join(args.docs, f)
            if os.path.isfile(fp):
                with open(fp, errors="replace") as fh:
                    docs.append({"id": f, "content": fh.read()})
    else:
        with open(args.docs, errors="replace") as fh:
            docs = [{"id": args.docs, "content": fh.read()}]

    system_prompt = None
    if args.system_prompt:
        with open(args.system_prompt) as fh:
            system_prompt = fh.read()

    report = scan_rag(docs, system_prompt=system_prompt, baseline_hash=args.baseline_hash)
    report.summary()


def cmd_eval_run(args) -> None:
    from sentrix import init
    init(persist=True)

    # Load experiment file
    import runpy
    ns = runpy.run_path(args.file)
    exp = ns.get("experiment") or ns.get("exp")
    if exp is None:
        print("[sentrix] Error: file must define 'experiment' or 'exp' variable")
        sys.exit(1)

    results = exp.run()
    results.summary()

    if args.fail_below and results.pass_rate < args.fail_below:
        print(f"[sentrix] FAIL: pass rate {results.pass_rate:.1%} < {args.fail_below:.1%}")
        sys.exit(1)


def cmd_monitor_watch(args) -> None:
    from sentrix import init
    from sentrix.monitor.daemon import watch
    init(persist=True)

    fn = _load_fn(args.target)
    plugins = [p.strip() for p in args.plugins.split(",")] if args.plugins else ["jailbreak", "pii"]
    watch(fn, interval_seconds=args.interval, plugins=plugins, n_attacks=args.n, alert_webhook=args.webhook)


def cmd_monitor_drift(args) -> None:
    from sentrix import init
    from sentrix.monitor.drift import DriftDetector
    init(persist=True)

    detector = DriftDetector(on_drift="warn" if not args.fail else "raise")
    detector.baseline(args.baseline)
    report = detector.check(window_hours=args.window)
    report.summary()


def cmd_monitor_traces(args) -> None:
    from sentrix.db import _q
    rows = _q("SELECT id, name, start_time, end_time, user_id, error FROM traces ORDER BY start_time DESC LIMIT ?", (args.limit,))
    if not rows:
        print("[sentrix] No traces found.")
        return
    print(f"\n{'ID':^38} {'Name':<25} {'Start':^20} {'Error'}")
    print("-" * 90)
    import datetime
    for r in rows:
        ts = datetime.datetime.fromtimestamp(r["start_time"]).strftime("%Y-%m-%d %H:%M:%S") if r["start_time"] else "-"
        print(f"{r['id']:<38} {(r['name'] or '-'):<25} {ts:<20} {r['error'] or '-'}")


def cmd_review_list(args) -> None:
    from sentrix.review.annotations import ReviewQueue
    q = ReviewQueue()
    if args.pending:
        items = q.pending()
        print(f"\n[sentrix] {len(items)} pending review items:")
        for item in items[:20]:
            print(f"  [{item['plugin']}] {item['attack_input'][:80]}...")
    else:
        anns = q.list_annotations(limit=args.limit)
        print(f"\n[sentrix] {len(anns)} annotations:")
        for a in anns:
            print(f"  [{a.label}] {a.result_id[:40]} — {a.comment or ''}")


def cmd_review_annotate(args) -> None:
    from sentrix.review.annotations import annotate
    ann = annotate(args.result_id, args.label, reviewer=args.reviewer, comment=args.comment)
    print(f"[sentrix] Annotated {ann.result_id} as '{ann.label}'")


def cmd_compliance(args) -> None:
    from sentrix import init
    from sentrix.compliance import generate_report
    init(persist=True)

    for framework in args.framework:
        report = generate_report(framework, output=args.output)
        report.summary()


def cmd_plugin_list(args) -> None:
    from sentrix.plugins import list_available, list_installed
    print("\n[sentrix] Available plugins:")
    for p in list_available():
        print(f"  {p['name']:<30} {p['description']}")
    print("\n[sentrix] Installed plugins:")
    for p in list_installed():
        print(f"  {p['name']:<30} v{p.get('version', '?')}")


def cmd_plugin_install(args) -> None:
    from sentrix.plugins import install
    install(args.name)


def cmd_serve(args) -> None:
    from sentrix.server.app import run
    run(port=args.port, db_path=args.db, no_open=args.no_open)


def cmd_history(args) -> None:
    from sentrix.db import _q, init_db
    init_db()
    rows = _q("SELECT target_fn, model, vulnerability_rate, total_cost_usd, created_at FROM red_team_reports ORDER BY created_at DESC LIMIT ?", (args.limit,))
    if not rows:
        print("[sentrix] No scan history found. Run sentrix scan first.")
        return
    import datetime
    print(f"\n{'Target':<30} {'Model':<15} {'Vuln%':>8} {'Cost':>10} {'Date'}")
    print("-" * 75)
    for r in rows:
        ts = datetime.datetime.fromtimestamp(r["created_at"]).strftime("%Y-%m-%d") if r["created_at"] else "-"
        rate = f"{r['vulnerability_rate']:.1%}" if r["vulnerability_rate"] is not None else "-"
        cost = f"${r['total_cost_usd']:.4f}" if r["total_cost_usd"] else "-"
        print(f"{(r['target_fn'] or '-'):<30} {(r['model'] or '-'):<15} {rate:>8} {cost:>10} {ts}")


def cmd_costs(args) -> None:
    from sentrix.db import _q, init_db
    import time
    init_db()
    cutoff = time.time() - args.days * 86400
    rows = _q("SELECT model, SUM(cost_usd) as total, COUNT(*) as calls FROM llm_calls WHERE timestamp > ? GROUP BY model ORDER BY total DESC", (cutoff,))
    if not rows:
        print(f"[sentrix] No LLM calls in the last {args.days} days.")
        return
    print(f"\nLLM Costs — last {args.days} days:")
    print(f"  {'Model':<30} {'Calls':>8} {'Total Cost':>12}")
    print("  " + "-" * 54)
    total = 0.0
    for r in rows:
        print(f"  {r['model']:<30} {r['calls']:>8} ${r['total']:>11.4f}")
        total += r["total"]
    print(f"\n  {'TOTAL':<30} {'':>8} ${total:>11.4f}")


def cmd_version(args) -> None:
    from sentrix import __version__
    print(f"sentrix v{__version__}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentrix",
        description="Red-team, eval, and monitor your LLMs.",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Red team a function")
    p_scan.add_argument("target", help="module:function")
    p_scan.add_argument("--plugins", default="jailbreak,pii,harmful")
    p_scan.add_argument("--n", type=int, default=10, help="Attacks per plugin")
    p_scan.add_argument("--git-compare", dest="git_compare", metavar="REF")
    p_scan.add_argument("--fail-on-regression", action="store_true", dest="fail_on_regression")
    p_scan.add_argument("--output", metavar="FILE")
    p_scan.set_defaults(func=cmd_scan)

    # fingerprint
    p_fp = sub.add_parser("fingerprint", help="Attack heatmap across models")
    p_fp.add_argument("targets", nargs="+", help="module:function pairs")
    p_fp.add_argument("--plugins", default="jailbreak,pii,harmful")
    p_fp.add_argument("--n", type=int, default=10)
    p_fp.set_defaults(func=cmd_fingerprint)

    # auto-dataset
    p_ds = sub.add_parser("auto-dataset", help="Generate test dataset from function")
    p_ds.add_argument("target", help="module:function")
    p_ds.add_argument("--n", type=int, default=20)
    p_ds.add_argument("--focus", default="mixed", choices=["adversarial", "normal", "edge_case", "mixed"])
    p_ds.add_argument("--name")
    p_ds.set_defaults(func=cmd_auto_dataset)

    # scan-agent
    p_agent = sub.add_parser("scan-agent", help="Test agentic workflow security")
    p_agent.add_argument("target", help="module:function")
    p_agent.add_argument("--mcp", metavar="URL")
    p_agent.set_defaults(func=cmd_scan_agent)

    # scan-rag
    p_rag = sub.add_parser("scan-rag", help="Scan RAG corpus for poisoning and PII")
    p_rag.add_argument("--docs", required=True, metavar="PATH")
    p_rag.add_argument("--system-prompt", dest="system_prompt", metavar="FILE")
    p_rag.add_argument("--baseline-hash", dest="baseline_hash", metavar="HASH")
    p_rag.set_defaults(func=cmd_scan_rag)

    # eval run
    p_eval = sub.add_parser("eval", help="Evaluation commands")
    eval_sub = p_eval.add_subparsers(dest="eval_command")
    p_eval_run = eval_sub.add_parser("run")
    p_eval_run.add_argument("file", help="Python file defining 'experiment' variable")
    p_eval_run.add_argument("--fail-below", type=float, dest="fail_below", metavar="RATE")
    p_eval_run.set_defaults(func=cmd_eval_run)

    # monitor
    p_mon = sub.add_parser("monitor", help="Monitoring commands")
    mon_sub = p_mon.add_subparsers(dest="mon_command")

    p_watch = mon_sub.add_parser("watch")
    p_watch.add_argument("target", help="module:function")
    p_watch.add_argument("--interval", type=int, default=60)
    p_watch.add_argument("--plugins", default="jailbreak,pii")
    p_watch.add_argument("--n", type=int, default=5)
    p_watch.add_argument("--webhook", metavar="URL")
    p_watch.set_defaults(func=cmd_monitor_watch)

    p_drift = mon_sub.add_parser("drift")
    p_drift.add_argument("--baseline", required=True, metavar="EXP_NAME")
    p_drift.add_argument("--window", type=float, default=24.0, metavar="HOURS")
    p_drift.add_argument("--fail", action="store_true")
    p_drift.set_defaults(func=cmd_monitor_drift)

    p_traces = mon_sub.add_parser("traces")
    p_traces.add_argument("--limit", type=int, default=20)
    p_traces.set_defaults(func=cmd_monitor_traces)

    # review
    p_rev = sub.add_parser("review", help="Human review workflow")
    rev_sub = p_rev.add_subparsers(dest="rev_command")

    p_rev_list = rev_sub.add_parser("list")
    p_rev_list.add_argument("--pending", action="store_true")
    p_rev_list.add_argument("--limit", type=int, default=20)
    p_rev_list.set_defaults(func=cmd_review_list)

    p_rev_ann = rev_sub.add_parser("annotate")
    p_rev_ann.add_argument("result_id")
    p_rev_ann.add_argument("--label", required=True, choices=["true_positive", "false_positive", "needs_review"])
    p_rev_ann.add_argument("--reviewer")
    p_rev_ann.add_argument("--comment")
    p_rev_ann.set_defaults(func=cmd_review_annotate)

    # compliance
    p_comp = sub.add_parser("compliance", help="Generate compliance reports")
    p_comp.add_argument("--framework", action="append", default=[], dest="framework",
                        choices=["owasp_llm_top10", "nist_ai_rmf", "eu_ai_act", "soc2"],
                        help="Framework to report on (can specify multiple)")
    p_comp.add_argument("--output", metavar="FILE")
    p_comp.set_defaults(func=cmd_compliance, framework=["owasp_llm_top10"])

    # plugin
    p_plug = sub.add_parser("plugin", help="Plugin ecosystem")
    plug_sub = p_plug.add_subparsers(dest="plug_command")
    plug_sub.add_parser("list").set_defaults(func=cmd_plugin_list)
    p_install = plug_sub.add_parser("install")
    p_install.add_argument("name")
    p_install.set_defaults(func=cmd_plugin_install)

    # serve
    p_serve = sub.add_parser("serve", help="Start dashboard")
    p_serve.add_argument("--port", type=int, default=7234)
    p_serve.add_argument("--db", metavar="PATH")
    p_serve.add_argument("--no-open", action="store_true", dest="no_open")
    p_serve.set_defaults(func=cmd_serve)

    # history / costs / version
    p_hist = sub.add_parser("history", help="Show scan history")
    p_hist.add_argument("--limit", type=int, default=20)
    p_hist.set_defaults(func=cmd_history)

    p_costs = sub.add_parser("costs", help="Show LLM costs")
    p_costs.add_argument("--days", type=int, default=7)
    p_costs.set_defaults(func=cmd_costs)

    sub.add_parser("version").set_defaults(func=cmd_version)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
