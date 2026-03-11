"""sentrix.plugins — Community plugin ecosystem."""
from sentrix.plugins.registry import install, list_installed, list_available, uninstall

__all__ = ["install", "list_installed", "list_available", "uninstall"]
