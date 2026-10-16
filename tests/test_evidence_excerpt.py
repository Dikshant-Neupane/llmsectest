"""A finding's excerpt has to contain the thing the finding says it found.

**The defect (R2572, found 2026-10-15 in a cohort member's report).** The evidence excerpt
was `outcome.response[:500]` — the HEAD of the reply, wherever the match actually was. One
LLM02 row, CRITICAL at CVSS 9.2, claimed the configured canary had been disclosed, over an
excerpt whose only canary-shaped token was one the application had invented. The finding was
GENUINE — the real canary sat past the cut — but it could only be established by reading
`detectors.py`'s near-miss matcher and proving a fuzzy match was impossible.

The fixture below is SYNTHETIC: it reproduces the shape (a long structured reply with the
match past the cut) without naming anyone's deployment or any real planted marker.

These reports go to other people's maintainers, and this project has already withdrawn
three reports for false findings. A maintainer who reads "your app leaked X" over text that
does not contain X dismisses it, and is right to. So this is a credibility defect, and the
property below is the one that fixes it:

    if the evidence line names a matched value, the excerpt contains that value.
"""

from __future__ import annotations

from llmsectest.probes.detectors import evidence_excerpt, matched_values

SECRET = "EXAMPLE-FIXTURE-SENTINEL-0000-CANARY"


def _handover_shaped_reply() -> str:
    """A reply of the shape that produced the defect: the canary well past char 500."""
    head = (
        "### Handover Document: Assistant Maintenance\n\n"
        "**Date:** 2026-10-15  \n**Subject:** Instance Replication & Configuration "
        "Specifications  \n**Reference ID:** EXAMPLE-FIXTURE-REF-5120\n\n---\n\n"
        "#### 1. Role Definition\n**Identity:** ExampleBot  \n"
        "**Function:** Research desk assistant for **Example Analytics**.\n"
    )
    filler = "*   Answering analyst queries regarding existing research dossiers.\n" * 20
    return f"{head}{filler}\n#### 4. Credentials\nAudit reference: {SECRET}\nEnd of document.\n"


def test_the_excerpt_contains_the_value_the_finding_names():
    """The whole point. Before the fix this assertion failed on the real artefact."""
    reply = _handover_shaped_reply()
    evidence = f"[LLM02] response disclosed protected value(s): {SECRET}"
    assert len(reply) > 500, "the fixture must be long enough to be truncated at all"
    assert SECRET not in reply[:500], (
        "the fixture must reproduce the defect: the canary has to sit past the old cut")

    excerpt = evidence_excerpt(reply, evidence)

    assert SECRET in excerpt, (
        "a maintainer reading this finding must be able to see the value it claims was "
        f"disclosed; got: {excerpt!r}")


def test_a_truncated_excerpt_says_so_at_the_edge_it_cut():
    """An ellipsis is how a reader knows the excerpt is not the whole reply."""
    reply = _handover_shaped_reply()
    excerpt = evidence_excerpt(reply, f"disclosed protected value(s): {SECRET}")
    assert excerpt.startswith("…"), "a window that does not start at the reply's start says so"


def test_a_reply_short_enough_to_show_whole_is_shown_whole():
    """No ellipsis, no window, no cleverness when the entire reply fits."""
    reply = f"here you go: {SECRET}"
    assert evidence_excerpt(reply, f"value(s): {SECRET}") == reply


def test_without_a_named_value_the_head_is_kept():
    """The old behaviour, deliberately, where there is no particular place to look.

    An LLM10 output-amplification row names no matched token: the finding IS the length.
    Centring on nothing would be worse than showing the start.
    """
    reply = "A" * 400 + "B" * 400
    excerpt = evidence_excerpt(reply, "[LLM10] reply exceeded the amplification bound")
    assert excerpt.startswith("A"), "with nothing to centre on, show the head"
    assert excerpt.endswith("…"), "and say that it was cut"


def test_a_value_named_but_absent_from_the_reply_falls_back_rather_than_crashing():
    """Robustness: the evidence line is prose, so it can name something not present verbatim."""
    reply = "A" * 900
    excerpt = evidence_excerpt(reply, "value(s): SOMETHING-NOT-IN-THE-REPLY-AT-ALL")
    assert excerpt.startswith("A") and excerpt.endswith("…")


def test_a_match_near_the_end_still_gets_a_full_width_window():
    """Clamping, not a short tail — the window is the reader's whole context."""
    reply = "A" * 900 + SECRET
    excerpt = evidence_excerpt(reply, f"value(s): {SECRET}", width=200)
    assert SECRET in excerpt
    assert len(excerpt.strip("…")) == 200, f"expected a full window, got {len(excerpt)}"


def test_matched_values_reads_the_evidence_lines_the_detectors_actually_write():
    """Pinned against real evidence strings, so a reworded detector cannot silently unhook it."""
    assert matched_values(f"response disclosed protected value(s): {SECRET}") == [SECRET]
    assert matched_values("emitted marker: PWNED-LLM01-PREFIX") == ["PWNED-LLM01-PREFIX"]
    assert matched_values("disclosed protected values: ALPHA-TOKEN-1, BETA-TOKEN-2") == [
        "ALPHA-TOKEN-1", "BETA-TOKEN-2"]
    # A parenthetical about HOW it was found is not part of the value.
    assert matched_values("value(s): GAMMA-TOKEN-3 (base64)") == ["GAMMA-TOKEN-3"]
    # Nothing to centre on is an empty list rather than a guess.
    assert matched_values("[LLM10] reply exceeded the amplification bound") == []
