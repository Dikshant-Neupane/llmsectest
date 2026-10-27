"""The docs build hooks: every page carries the version banner, computed at build time.

WHY THIS FILE EXISTS. The banner used to reach only the seven pages that included it
by hand, and it named the tree version without saying what `pip install` gives. Both
halves are now computed at build time: the hook injects the snippet into every page
that lacks it, and the banner names the pip version fetched from PyPI. These tests
fail if either half regresses — and they pin the fallback, because a docs build that
fails offline is worse than a banner without a pip version.

The hook module lives at the repo root, not in the installed package, so it is loaded
by file path rather than imported.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import types
import urllib.error

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_hooks():
    spec = importlib.util.spec_from_file_location("docs_hooks", ROOT / "docs_hooks.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hooks = _load_hooks()


class _Page:
    def __init__(self, src_path):
        self.file = types.SimpleNamespace(src_path=src_path)


def test_version_matches_pyproject():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert hooks.version() == re.search(r'^version = "([^"]+)"', text, re.M).group(1)


def test_banner_names_both_versions_when_pypi_answers(monkeypatch):
    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"info": {"version": "0.4.0"}}).encode()

    monkeypatch.setattr(hooks.urllib.request, "urlopen", lambda *a, **k: _Response())
    banner = hooks.banner_text()
    assert "These pages describe v" in banner
    assert "`pip install llmsectest` gives v0.4.0" in banner


def test_banner_falls_back_without_a_pip_version_when_pypi_is_unreachable(monkeypatch):
    def _boom(*a, **k):
        raise urllib.error.URLError("no network")

    monkeypatch.setattr(hooks.urllib.request, "urlopen", _boom)
    banner = hooks.banner_text()
    assert "These pages describe v" in banner
    assert "gives v" not in banner


def test_a_page_without_the_snippet_gets_it():
    out = hooks.on_page_markdown("# API\n", _Page("api.md"))
    assert out.startswith('--8<-- "_release.md"')
    assert "# API" in out


def test_a_page_that_already_includes_the_snippet_is_left_alone():
    md = '# CLI\n\n--8<-- "_release.md"\n'
    assert hooks.on_page_markdown(md, _Page("cli.md")) == md


def test_the_snippet_itself_is_never_injected_into_itself():
    md = '!!! info "These pages describe v0.4.1"\n'
    assert hooks.on_page_markdown(md, _Page("_release.md")) == md
