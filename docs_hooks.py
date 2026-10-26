"""Build-time hooks for the documentation site.

`on_pre_build` writes `docs/_release.md`, the snippet every page that documents a flag
includes. It exists because the two halves a reader uses come from different places:
`docs.llmsec.dev` is deployed from `main` on every push, and `pip install llmsectest` gives
the last upload to PyPI. Between a release and the next one the site documents flags the
released tool refuses, which on 2026-09-05 was seven of them for fifteen days and cost a
release to close. Nothing on the page said which of the two a reader was looking at.

Generated rather than typed: the same page carried a hand-written `v0.2.0` badge for two
hours after 0.3.0 was on PyPI, and eight copies of it across the website went stale at once.

Two halves the first version left out, fixed here. The snippet reached only the seven
pages that included it by hand, so a reader landing on an OWASP page or the API page saw
no version at all: `on_page_markdown` now injects the include into every page that lacks
it. And the banner named the tree version without saying what `pip install` gives, so
`on_pre_build` now fetches that from PyPI too — with a fallback to the banner without a
pip version when PyPI cannot be reached, because a docs build that fails offline is worse
than a banner without one number.
"""
from __future__ import annotations

import json
import pathlib
import re
import urllib.error
import urllib.request

BANNER = """!!! info "These pages describe {version}"

    The site is built from `main`, so it can describe a version newer than the one
    `pip install llmsectest` gives you. Run `llmsectest --version` to see what you have.
    [The changelog](https://docs.llmsec.dev/changelog/) says what arrived when.
"""

BANNER_PIP = """!!! info "These pages describe {version}; `pip install llmsectest` gives {pip_version}"

    The site is built from `main`, so it can describe a version newer than the one
    `pip install llmsectest` gives you. Run `llmsectest --version` to see what you have.
    [The changelog](https://docs.llmsec.dev/changelog/) says what arrived when.
"""


def version() -> str:
    """The version this tree builds, read from the one file the packaging uses."""
    root = pathlib.Path(__file__).resolve().parent
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    return re.search(r'^version = "([^"]+)"', text, re.M).group(1)


def pip_version(timeout: float = 10.0) -> str | None:
    """The version `pip install llmsectest` gives today, or None if PyPI is unreachable.

    Queried at build time, never typed: a typed pip version goes stale at the next
    release exactly like the hand-written badge this hook replaced. Any failure —
    no network, a slow PyPI, an unexpected payload — returns None so the docs build
    stays green offline; the caller falls back to the banner without a pip version.
    """
    request = urllib.request.Request(
        "https://pypi.org/pypi/llmsectest/json",
        headers={"User-Agent": "llmsectest-docs-hook"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return str(payload["info"]["version"])
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


def banner_text() -> str:
    """The banner for this build: tree version, plus the pip version when known."""
    pip = pip_version()
    if pip is None:
        return BANNER.format(version=f"v{version()}")
    return BANNER_PIP.format(version=f"v{version()}", pip_version=f"v{pip}")


def on_pre_build(config, **kwargs) -> None:
    target = pathlib.Path(__file__).resolve().parent / "docs" / "_release.md"
    target.write_text(banner_text(), encoding="utf-8")


def on_page_markdown(markdown: str, page, **kwargs) -> str:
    """Give every page the release banner, not just the pages that include it by hand.

    Seven pages carry `--8<-- "_release.md"` explicitly; the other sixteen do not, so a
    reader landing on an OWASP page or the API page saw no version at all. Pages that
    already include the snippet are left alone (injecting again would print the banner
    twice), and `_release.md` itself is skipped (it IS the snippet; including itself
    would recurse). The injected line is the same snippet include the hand-written
    pages use, so it resolves the same way: the snippets extension runs during
    conversion, after this hook.
    """
    if page.file.src_path == "_release.md":
        return markdown
    if "_release.md" in markdown:
        return markdown
    return '--8<-- "_release.md"\n\n' + markdown
