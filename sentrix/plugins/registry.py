"""Community plugin registry — install/list/uninstall sentrix plugins."""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.request
import urllib.error

_REGISTRY_URL = "https://raw.githubusercontent.com/pinexai/sentrix-plugins/main/plugins.json"

# Bundled known plugins (fallback if registry unreachable)
_KNOWN_PLUGINS = [
    {
        "name": "advanced-jailbreak",
        "pypi": "sentrix-plugin-advanced-jailbreak",
        "description": "Extended jailbreak attack templates with 50+ vectors",
        "author": "sentrix-team",
        "type": "attack",
    },
    {
        "name": "medical-safety",
        "pypi": "sentrix-plugin-medical-safety",
        "description": "Medical advice safety testing for healthcare AI",
        "author": "sentrix-team",
        "type": "attack",
    },
    {
        "name": "legal-compliance",
        "pypi": "sentrix-plugin-legal-compliance",
        "description": "Legal advice boundary testing",
        "author": "sentrix-team",
        "type": "attack",
    },
    {
        "name": "multilingual-jailbreak",
        "pypi": "sentrix-plugin-multilingual-jailbreak",
        "description": "Jailbreak attacks in 20+ languages",
        "author": "community",
        "type": "attack",
    },
]


def list_available() -> list[dict]:
    """Fetch available plugins from the community registry."""
    try:
        with urllib.request.urlopen(_REGISTRY_URL, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception:
        return _KNOWN_PLUGINS


def list_installed() -> list[dict]:
    """Return plugins currently installed in the Python environment."""
    installed = []
    for plugin in _KNOWN_PLUGINS:
        pypi = plugin["pypi"]
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "show", pypi],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                # Parse version from pip show output
                version = "unknown"
                for line in result.stdout.splitlines():
                    if line.startswith("Version:"):
                        version = line.split(":", 1)[1].strip()
                installed.append({**plugin, "version": version, "status": "installed"})
        except Exception:
            pass
    return installed


def install(plugin_name: str, source: str = "sentrix-hub") -> None:
    """
    Install a community plugin.

    Usage:
        sentrix.plugins.install("advanced-jailbreak")
    """
    # Find the PyPI package name
    pypi_name = None
    for p in _KNOWN_PLUGINS:
        if p["name"] == plugin_name or p["pypi"] == plugin_name:
            pypi_name = p["pypi"]
            break

    if pypi_name is None:
        # Try conventional naming
        pypi_name = f"sentrix-plugin-{plugin_name}"

    print(f"[sentrix] Installing plugin '{plugin_name}' ({pypi_name})...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", pypi_name],
        capture_output=False,
    )
    if result.returncode == 0:
        print(f"[sentrix] Plugin '{plugin_name}' installed successfully.")
        _register_installed(plugin_name, pypi_name)
    else:
        print(f"[sentrix] Failed to install '{plugin_name}'.")


def uninstall(plugin_name: str) -> None:
    """Uninstall a community plugin."""
    pypi_name = f"sentrix-plugin-{plugin_name}"
    for p in _KNOWN_PLUGINS:
        if p["name"] == plugin_name:
            pypi_name = p["pypi"]
            break

    print(f"[sentrix] Uninstalling plugin '{plugin_name}'...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "uninstall", "-y", pypi_name],
        capture_output=False,
    )
    if result.returncode == 0:
        print(f"[sentrix] Plugin '{plugin_name}' uninstalled.")
    else:
        print(f"[sentrix] Failed to uninstall '{plugin_name}'.")


def _register_installed(name: str, pypi: str) -> None:
    """Track installed plugins in sentrix DB."""
    try:
        from sentrix.guard.attacks import PLUGIN_REGISTRY
        # Dynamic import and register
        module_name = pypi.replace("-", "_")
        import importlib
        mod = importlib.import_module(f"{module_name}.plugin")
        cls = getattr(mod, list(vars(mod).keys())[-1])
        if hasattr(cls, "name") and hasattr(cls, "generate"):
            PLUGIN_REGISTRY[cls.name] = cls
            print(f"[sentrix] Registered plugin '{cls.name}' in PLUGIN_REGISTRY")
    except Exception:
        pass
