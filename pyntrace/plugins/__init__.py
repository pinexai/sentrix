"""pyntrace.plugins — Community plugin ecosystem."""
from pyntrace.plugins.registry import install, list_installed, list_available, uninstall

__all__ = ["install", "list_installed", "list_available", "uninstall"]
