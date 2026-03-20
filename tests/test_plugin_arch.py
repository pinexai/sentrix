"""Tests for the attack plugin architecture."""
from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from pyntrace.guard.attacks import (
    PLUGIN_REGISTRY,
    AttackPlugin,
    _FunctionPlugin,
    attack_plugin,
    load_all_plugins,
    load_entry_point_plugins,
    load_file_plugins,
    register_plugin,
)


# ── Built-in registry ─────────────────────────────────────────────────────────

class TestBuiltinPlugins:
    def test_all_builtin_keys_present(self):
        for name in ("jailbreak", "pii", "harmful", "hallucination", "injection", "competitor"):
            assert name in PLUGIN_REGISTRY

    def test_builtin_generate_returns_list(self):
        for name, cls in PLUGIN_REGISTRY.items():
            plugin = cls()
            results = plugin.generate(5)
            assert isinstance(results, list)
            assert len(results) <= 5

    def test_jailbreak_generates_nonempty(self):
        from pyntrace.guard.attacks import JailbreakPlugin
        results = JailbreakPlugin().generate(10)
        assert len(results) == 10
        assert all(isinstance(r, str) and len(r) > 0 for r in results)

    def test_pii_templates_count(self):
        from pyntrace.guard.attacks import PIIPlugin
        assert len(PIIPlugin._TEMPLATES) == 18  # 18 templates defined


# ── register_plugin + _FunctionPlugin ────────────────────────────────────────

class TestRegisterPlugin:
    def _cleanup(self, name: str):
        PLUGIN_REGISTRY.pop(name, None)

    def test_register_callable(self):
        def my_fn(prompt: str) -> list[str]:
            return [f"attack: {prompt}", "static attack"]

        register_plugin("_test_reg", my_fn)
        try:
            assert "_test_reg" in PLUGIN_REGISTRY
            plugin = PLUGIN_REGISTRY["_test_reg"]()
            results = plugin.generate(5)
            assert isinstance(results, list)
        finally:
            self._cleanup("_test_reg")

    def test_register_overrides_existing(self):
        def fn1(prompt): return ["v1"]
        def fn2(prompt): return ["v2"]
        register_plugin("_test_override", fn1)
        register_plugin("_test_override", fn2)
        try:
            results = PLUGIN_REGISTRY["_test_override"]().generate(1)
            assert results == ["v2"]
        finally:
            self._cleanup("_test_override")

    def test_function_plugin_name_and_category(self):
        def fn(prompt): return []
        register_plugin("_test_meta", fn)
        try:
            plugin = PLUGIN_REGISTRY["_test_meta"]()
            assert plugin.name == "_test_meta"
            assert plugin.category == "custom"
        finally:
            self._cleanup("_test_meta")

    def test_generate_truncates_to_n(self):
        def fn(prompt): return ["a", "b", "c", "d", "e"]
        register_plugin("_test_trunc", fn)
        try:
            results = PLUGIN_REGISTRY["_test_trunc"]().generate(3)
            assert len(results) == 3
        finally:
            self._cleanup("_test_trunc")

    def test_no_arg_function_also_works(self):
        """Plugin functions that take no arguments should still work."""
        def fn(): return ["no-arg attack"]
        register_plugin("_test_noarg", fn)
        try:
            results = PLUGIN_REGISTRY["_test_noarg"]().generate(5)
            assert "no-arg attack" in results
        finally:
            self._cleanup("_test_noarg")


# ── @attack_plugin decorator ──────────────────────────────────────────────────

class TestAttackPluginDecorator:
    def test_decorator_registers_and_returns_function(self):
        @attack_plugin("_test_decorator")
        def my_fn(prompt: str) -> list[str]:
            return [f"decorated: {prompt}"]

        try:
            assert "_test_decorator" in PLUGIN_REGISTRY
            # The original function is still callable
            assert my_fn("hello") == ["decorated: hello"]
        finally:
            PLUGIN_REGISTRY.pop("_test_decorator", None)

    def test_decorator_plugin_generates(self):
        @attack_plugin("_test_deco_gen")
        def attacks(prompt: str) -> list[str]:
            return ["attack1", "attack2", "attack3"]

        try:
            plugin = PLUGIN_REGISTRY["_test_deco_gen"]()
            results = plugin.generate(10)
            assert set(results) == {"attack1", "attack2", "attack3"}
        finally:
            PLUGIN_REGISTRY.pop("_test_deco_gen", None)


# ── Entry-point plugin loading ────────────────────────────────────────────────

class TestEntryPointPlugins:
    def test_load_entry_point_plugins_no_crash_when_empty(self):
        """Should not raise even when no entry points exist."""
        load_entry_point_plugins()

    def test_load_entry_point_plugins_registers_ep(self, monkeypatch):
        def fake_fn(prompt): return ["ep attack"]

        class FakeEP:
            name = "_test_ep"
            def load(self): return fake_fn

        def fake_entry_points(group):
            return [FakeEP()]

        import importlib.metadata
        monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)
        load_entry_point_plugins()
        try:
            assert "_test_ep" in PLUGIN_REGISTRY
        finally:
            PLUGIN_REGISTRY.pop("_test_ep", None)

    def test_broken_entry_point_emits_warning(self, monkeypatch):
        class BrokenEP:
            name = "_test_broken"
            def load(self): raise ImportError("missing dep")

        import importlib.metadata
        monkeypatch.setattr(importlib.metadata, "entry_points", lambda group: [BrokenEP()])
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            load_entry_point_plugins()
        assert any("_test_broken" in str(x.message) for x in w)


# ── File-based plugin loading ─────────────────────────────────────────────────

class TestFilePlugins:
    def test_load_from_nonexistent_dir_no_crash(self):
        load_file_plugins(Path("/nonexistent/plugin/dir"))

    def test_load_py_file_plugin(self, tmp_path):
        plugin_file = tmp_path / "my_plugin.py"
        plugin_file.write_text(
            'PYNTRACE_PLUGIN_NAME = "file_loaded_plugin"\n'
            'def generate(prompt): return ["file attack"]\n'
        )
        load_file_plugins(tmp_path)
        try:
            assert "file_loaded_plugin" in PLUGIN_REGISTRY
            plugin = PLUGIN_REGISTRY["file_loaded_plugin"]()
            assert "file attack" in plugin.generate(5)
        finally:
            PLUGIN_REGISTRY.pop("file_loaded_plugin", None)

    def test_plugin_name_defaults_to_stem(self, tmp_path):
        plugin_file = tmp_path / "stem_name.py"
        plugin_file.write_text("def generate(prompt): return ['attack']\n")
        load_file_plugins(tmp_path)
        try:
            assert "stem_name" in PLUGIN_REGISTRY
        finally:
            PLUGIN_REGISTRY.pop("stem_name", None)

    def test_broken_plugin_file_emits_warning(self, tmp_path):
        plugin_file = tmp_path / "broken.py"
        plugin_file.write_text("raise SyntaxError('oops')\n")
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            load_file_plugins(tmp_path)
        assert any("broken" in str(x.message) for x in w)

    def test_load_all_plugins_calls_both(self, tmp_path):
        """load_all_plugins() should not crash."""
        load_all_plugins()
