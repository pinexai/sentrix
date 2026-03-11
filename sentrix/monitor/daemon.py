"""Continuous monitoring daemon — watch mode for ongoing red team scanning."""
from __future__ import annotations

import json
import signal
import threading
import time
import uuid
from typing import Callable


def watch(
    fn: Callable,
    interval_seconds: int = 60,
    plugins: tuple | list = ("jailbreak", "pii"),
    n_attacks: int = 5,
    alert_webhook: str | None = None,
    on_regression: str = "alert",  # "alert" | "raise" | "log"
) -> None:
    """
    Run as a continuous monitoring daemon.
    Every interval_seconds, runs a mini red-team scan and alerts on regression.

    This is a blocking call. Use Ctrl+C or SIGTERM to stop.

    Args:
        fn: the function to monitor
        interval_seconds: how often to run scans
        plugins: attack plugins to use (keep small for speed)
        n_attacks: attacks per plugin per run
        alert_webhook: URL to POST alerts to
        on_regression: "alert" | "raise" | "log"
    """
    fn_name = getattr(fn, "__name__", str(fn))
    print(f"[sentrix] Starting monitoring daemon for {fn_name!r}")
    print(f"  Interval : {interval_seconds}s")
    print(f"  Plugins  : {', '.join(plugins)}")
    print(f"  Attacks  : {n_attacks} per plugin")
    print("  Press Ctrl+C to stop.\n")

    baseline_rate: float | None = None
    stop_event = threading.Event()

    def _handle_signal(sig, frame):
        print("\n[sentrix] Stopping daemon...")
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    while not stop_event.is_set():
        try:
            from sentrix.guard.red_team import red_team
            report = red_team(fn, plugins=plugins, n_attacks=n_attacks, _persist=True)
            current_rate = report.vulnerability_rate

            print(f"[{time.strftime('%H:%M:%S')}] Scan complete — vuln rate: {current_rate:.1%} (cost: ${report.total_cost_usd:.4f})")

            if baseline_rate is None:
                baseline_rate = current_rate
                print(f"  Baseline established: {baseline_rate:.1%}")
            else:
                delta = current_rate - baseline_rate
                if delta > 0.1:  # 10% regression threshold
                    _handle_regression(
                        fn_name, delta, current_rate, baseline_rate,
                        alert_webhook, on_regression, report
                    )
                else:
                    print(f"  Delta: {delta:+.1%} — OK")

            _record_event(fn_name, current_rate, report.total_cost_usd, alert_sent=False)

        except Exception as e:
            print(f"[sentrix] Scan error: {e}")

        stop_event.wait(timeout=interval_seconds)


def _handle_regression(
    fn_name: str,
    delta: float,
    current_rate: float,
    baseline_rate: float,
    webhook: str | None,
    on_regression: str,
    report,
) -> None:
    msg = f"[sentrix] REGRESSION in {fn_name!r}: {baseline_rate:.1%} → {current_rate:.1%} (delta: {delta:+.1%})"
    print(f"  ⚠️  {msg}")

    if webhook:
        _send_webhook(webhook, msg, report)
        _record_event(fn_name, current_rate, report.total_cost_usd, alert_sent=True)

    if on_regression == "raise":
        raise RuntimeError(msg)
    elif on_regression == "log":
        import logging
        logging.warning(msg)
    # "alert" — just print + webhook


def _send_webhook(url: str, msg: str, report) -> None:
    import urllib.request
    try:
        payload = json.dumps({
            "text": msg,
            "vulnerability_rate": report.vulnerability_rate,
            "total_cost_usd": report.total_cost_usd,
            "by_plugin": report.by_plugin,
        }).encode()
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[sentrix] Webhook failed: {e}")


def _record_event(fn_name: str, vuln_rate: float, cost: float, alert_sent: bool) -> None:
    try:
        from sentrix.db import get_conn
        conn = get_conn()
        with conn:
            conn.execute(
                """INSERT INTO monitoring_events
                   (id, fn_name, vulnerability_rate, cost_usd, alert_sent, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (str(uuid.uuid4()), fn_name, vuln_rate, cost, 1 if alert_sent else 0, time.time()),
            )
        conn.close()
    except Exception:
        pass
