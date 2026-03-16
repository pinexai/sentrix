"""Attack heatmap / Model fingerprint — KILLER FEATURE #2."""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

from pyntrace.guard.red_team import red_team


@dataclass
class ModelVulnerability:
    model: str
    plugin: str
    attacks: int
    vulnerable: int
    rate: float


@dataclass
class ModelFingerprint:
    models: list[str]
    plugins: list[str]
    data: dict[str, dict[str, ModelVulnerability]]
    total_cost_usd: float
    created_at: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def heatmap(self) -> None:
        """Print a color-coded terminal heatmap."""
        RED = "\033[91m"
        YELLOW = "\033[93m"
        GREEN = "\033[92m"
        RESET = "\033[0m"
        BOLD = "\033[1m"

        def bar(rate: float) -> str:
            filled = int(rate * 10)
            return "█" * filled + "░" * (10 - filled)

        def colorize(rate: float, text: str) -> str:
            if rate > 0.4:
                return f"{RED}{text}{RESET}"
            elif rate > 0.2:
                return f"{YELLOW}{text}{RESET}"
            return f"{GREEN}{text}{RESET}"

        col_w = max(14, max(len(m) for m in self.models) + 2)
        plugin_w = 18

        print(f"\n{BOLD}Attack Heatmap{RESET} (total cost: ${self.total_cost_usd:.4f})")
        print()

        # Header
        header = f"  {'Plugin':<{plugin_w}}"
        for model in self.models:
            header += f" │ {model:^{col_w}}"
        print(header)
        print("  " + "─" * plugin_w + ("─┼─" + "─" * col_w) * len(self.models))

        # Rows
        for plugin in self.plugins:
            row = f"  {plugin:<{plugin_w}}"
            for model in self.models:
                vuln = self.data.get(model, {}).get(plugin)
                if vuln is None:
                    cell = f"{'N/A':^{col_w}}"
                    row += f" │ {cell}"
                else:
                    rate = vuln.rate
                    text = f"{bar(rate)} {rate:.0%}"
                    colored = colorize(rate, f"{text:^{col_w}}")
                    row += f" │ {colored}"
            print(row)

        print()
        print(f"  {GREEN}Green{RESET} <20%  {YELLOW}Yellow{RESET} 20-40%  {RED}Red{RESET} >40%")
        print()

    def most_vulnerable_model(self) -> str:
        model_rates = {}
        for model in self.models:
            rates = [v.rate for v in self.data.get(model, {}).values()]
            model_rates[model] = sum(rates) / len(rates) if rates else 0.0
        return max(model_rates, key=lambda m: model_rates[m])

    def safest_model(self) -> str:
        model_rates = {}
        for model in self.models:
            rates = [v.rate for v in self.data.get(model, {}).values()]
            model_rates[model] = sum(rates) / len(rates) if rates else 0.0
        return min(model_rates, key=lambda m: model_rates[m])

    def worst_attack_category(self, model: str) -> str:
        vulns = self.data.get(model, {})
        if not vulns:
            return "N/A"
        return max(vulns, key=lambda p: vulns[p].rate)

    def summary(self) -> None:
        print(f"\n[pyntrace] Model Fingerprint Summary")
        print(f"  Models tested  : {', '.join(self.models)}")
        print(f"  Plugins tested : {', '.join(self.plugins)}")
        print(f"  Total cost     : ${self.total_cost_usd:.4f}")
        print(f"  Most vulnerable: {self.most_vulnerable_model()}")
        print(f"  Safest model   : {self.safest_model()}")
        self.heatmap()

    def to_json(self) -> dict:
        data_serializable = {}
        for model, plugins in self.data.items():
            data_serializable[model] = {
                p: {
                    "model": v.model,
                    "plugin": v.plugin,
                    "attacks": v.attacks,
                    "vulnerable": v.vulnerable,
                    "rate": v.rate,
                }
                for p, v in plugins.items()
            }
        return {
            "id": self.id,
            "models": self.models,
            "plugins": self.plugins,
            "data": data_serializable,
            "total_cost_usd": self.total_cost_usd,
            "created_at": self.created_at,
        }

    def _persist(self) -> None:
        try:
            from pyntrace.db import get_conn
            conn = get_conn()
            d = self.to_json()
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO fingerprints
                       (id, models_json, plugins_json, data_json, total_cost_usd, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (self.id, json.dumps(d["models"]), json.dumps(d["plugins"]),
                     json.dumps(d["data"]), self.total_cost_usd, self.created_at),
                )
            conn.close()
        except Exception as e:
            print(f"[pyntrace] Warning: could not persist fingerprint: {e}")


def fingerprint(
    targets: dict[str, Callable],
    plugins: tuple | list = ("jailbreak", "pii", "harmful", "hallucination", "injection"),
    n_attacks: int = 10,
    judge_model: str | None = None,
    _persist: bool = True,
) -> ModelFingerprint:
    """
    Run attack plugins against multiple models simultaneously.
    Returns a ModelFingerprint with a vulnerability heatmap.

    Args:
        targets: {"model-name": callable} — each callable takes a prompt str, returns str
        plugins: attack plugin names to test
        n_attacks: attacks per plugin per model
        judge_model: LLM to judge responses

    Example:
        fp = pyntrace.guard.fingerprint({
            "gpt-4o-mini": gpt_fn,
            "claude-haiku": claude_fn,
        })
        fp.heatmap()
    """
    model_names = list(targets.keys())
    plugin_names = list(plugins)
    data: dict[str, dict[str, ModelVulnerability]] = {}
    total_cost = 0.0

    print(f"\n[pyntrace] Fingerprinting {len(model_names)} model(s) across {len(plugin_names)} attack plugin(s)...")

    for model_name, fn in targets.items():
        print(f"\n  Model: {model_name}")
        report = red_team(
            fn,
            plugins=plugins,
            n_attacks=n_attacks,
            judge_model=judge_model,
            _persist=False,
        )
        total_cost += report.total_cost_usd

        data[model_name] = {}
        for plugin_name, stats in report.by_plugin.items():
            data[model_name][plugin_name] = ModelVulnerability(
                model=model_name,
                plugin=plugin_name,
                attacks=stats["attacks"],
                vulnerable=stats["vulnerable"],
                rate=stats["rate"],
            )

    fp = ModelFingerprint(
        models=model_names,
        plugins=plugin_names,
        data=data,
        total_cost_usd=total_cost,
    )

    if _persist:
        fp._persist()

    return fp
