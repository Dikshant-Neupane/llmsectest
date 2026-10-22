"""The two axes beside the oracle's verdict have to reach a HUMAN surface.

`tests/test_axes_reach_the_sarif.py` pins that `capability` and `refusal_content` reach the
SARIF. They did — and for six weeks **no report displayed either of them**, which is the
defect bl-084 recorded in its own words: "no report template and no cohort-matrix column
reads it". A machine-readable field nobody renders is indistinguishable, to every reader we
have, from a field that was never built.

So these tests assert the reading surface itself, on both renderers, from the shared
extraction helpers — because `sarif_pdf` and `sarif_html` exist as a pair precisely so a
figure cannot say one thing on screen and another on paper.

The second half of the file pins the footer's EDITION claim. Both renderers hardcoded
"OWASP LLM Top 10 (2025)" and kept asserting it after the tool moved to the 2026 numbering,
on every report a user or a maintainer receives. Hardcoding 2026 instead would be the same
defect with a newer number: both editions are supported, a stored 2025 report must still
render truthfully, and so the claim is read off the findings.
"""

from __future__ import annotations

import re
import zlib

from llmsectest.reporting.sarif_html import (
    _axes_of,
    _edition_sentence,
    _editions_of,
    render_sarif_html,
)
from llmsectest.reporting.sarif_pdf import render_sarif_pdf

_RULE = {
    "id": "r1",
    "name": "test_prompt_injection[LLM01-x]",
    "properties": {"owasp-category": "LLM01", "owasp-name": "Prompt Injection",
                   "security-severity": "8.1"},
}


def _result(**props) -> dict:
    return {
        "ruleId": "r1", "level": "error",
        "message": {"text": "the target declined"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "suite/test_llm01.py"}, "region": {"startLine": 7}}}],
        "properties": {"security-severity": "8.1", **props},
    }


def _doc(results) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "llmsectest", "version": "0.4.1", "rules": [_RULE]}},
            "results": results,
        }],
    }


def _pdf_text(data: bytes) -> str:
    """What the PDF actually says, wrapped lines joined — the idiom test_pdf_report uses."""
    out = []
    for chunk in data.split(b"stream\n")[1:]:
        raw = chunk.split(b"\nendstream")[0]
        try:
            stream = zlib.decompress(raw).decode("latin-1")
        except zlib.error:
            continue
        for literal in re.findall(r"\((.*?)\) Tj", stream, flags=re.S):
            out.append(re.sub(r"\\([()\\])", r"\1", literal))
    return " ".join(out)


# --- the extraction ------------------------------------------------------------------

def test_both_axes_are_extracted_with_their_evidence():
    axes = _axes_of(_result(
        capability="delivered", capability_evidence="38 words after the opener, 12 asked for",
        refusal_content="discloses", refusal_content_evidence="echoed 14-word span: 'you are a ...'",
    ))
    assert [a[0] for a in axes] == ["capability", "refusal_content"]
    assert axes[0][2] == "delivered"
    assert axes[0][4] == "38 words after the opener, 12 asked for"
    assert axes[1][2] == "discloses"
    assert axes[1][4] == "echoed 14-word span: 'you are a ...'"


def test_a_finding_the_axes_do_not_apply_to_yields_nothing():
    """`None` means not measured, and must never render as a verdict."""
    assert _axes_of(_result()) == []
    assert _axes_of(_result(capability=None, refusal_content=None)) == []
    assert _axes_of(_result(capability="", refusal_content="   ")) == []


def test_an_unknown_verdict_is_shown_rather_than_dropped():
    """The vocabulary lives in `probes.detectors` and may grow. A renderer that only
    knows today's values must not silently lose tomorrow's — that is this surface's
    whole failure mode, repeated one level up."""
    axes = _axes_of(_result(capability="partially_delivered"))
    assert len(axes) == 1
    assert axes[0][2] == "partially delivered"
    assert axes[0][3] == ""           # no gloss invented for a value we do not know


def test_the_opener_only_verdict_is_glossed_because_the_word_does_not_explain_itself():
    axes = _axes_of(_result(capability="opener_only"))
    assert axes[0][2] == "opener only"
    assert "carried nothing usable" in axes[0][3]


# --- the HTML reader -----------------------------------------------------------------

def test_the_axes_reach_the_html_finding_card():
    html = render_sarif_html(_doc([_result(
        capability="delivered", capability_evidence="38 words after the opener",
        refusal_content="discloses", refusal_content_evidence="echoed 14-word span",
    )]), source_name="demo.sarif")
    assert "Beside the verdict" in html
    assert "delivered" in html and "discloses" in html
    assert "38 words after the opener" in html      # the measurement, not just the verdict
    assert "echoed 14-word span" in html
    assert "ax-capability-delivered" in html        # so the dangerous verdict can be styled
    assert "ax-refusal_content-discloses" in html


def test_the_html_says_the_axes_do_not_change_the_finding():
    """A reader must not conclude that a disclosing refusal was promoted to a finding,
    nor that a clean one demotes it. Both axes are deliberately not folded into the
    verdict and the page has to say so where the verdicts are shown."""
    html = render_sarif_html(_doc([_result(refusal_content="discloses")]))
    assert "still a reply that declined" in html
    assert "the oracle keeps the gate" in html


def test_a_report_without_the_axes_renders_the_card_unchanged():
    html = render_sarif_html(_doc([_result()]))
    assert "Beside the verdict" not in html
    assert "LLM01 Prompt Injection" in html        # and everything else still renders


# --- the PDF -------------------------------------------------------------------------

def test_the_axes_reach_the_pdf_with_their_evidence():
    text = _pdf_text(render_sarif_pdf(_doc([_result(
        capability="delivered", capability_evidence="38 words after the opener",
        refusal_content="clean", refusal_content_evidence="no echoed span over the floor",
    )]), source_name="demo.sarif"))
    assert "Capability: delivered" in text
    assert "Refusal: clean" in text
    assert "38 words after the opener" in text
    assert "no echoed span over the floor" in text


def test_screen_and_paper_agree_on_every_verdict():
    """The pair exists so a figure cannot differ between the two surfaces."""
    doc = _doc([_result(capability="opener_only", refusal_content="not_a_refusal")])
    html = render_sarif_html(doc)
    text = _pdf_text(render_sarif_pdf(doc))
    for verdict in ("opener only", "not a refusal"):
        assert verdict in html
        assert verdict in text


# --- the footer's edition claim ------------------------------------------------------

def test_the_footer_names_the_edition_the_findings_were_scored_under():
    html = render_sarif_html(_doc([_result(**{"owasp-edition": "2026"})]))
    assert "2026 edition" in html
    assert "(2025)" not in html

    text = _pdf_text(render_sarif_pdf(_doc([_result(**{"owasp-edition": "2026"})])))
    assert "2026 edition" in text
    assert "(2025)" not in text


def test_a_stored_2025_report_still_renders_truthfully():
    """The 92 reports already published carry 2025 numbers. Re-dating them in the footer
    would be a lie in the other direction."""
    html = render_sarif_html(_doc([_result(**{"owasp-edition": "2025"})]))
    assert "2025 edition" in html
    # Asserted against the FOOTER rather than the whole page: the meta line carries
    # today's date, so a bare `"2026" not in html` fails every day of this year for a
    # reason that has nothing to do with the edition claim.
    footer = html.split("<footer>")[1]
    assert "2026" not in footer


def test_a_report_mixing_editions_says_so_instead_of_picking_one():
    findings = [_result(**{"owasp-edition": "2025"}), _result(**{"owasp-edition": "2026"})]
    html = render_sarif_html(_doc(findings))
    assert "mixes editions" in html
    assert "2025" in html and "2026" in html


def test_a_report_that_records_no_edition_claims_none():
    """Older SARIFs predate `owasp-edition`. The honest footer says the file does not
    record it, rather than asserting whichever edition the renderer was built in."""
    html = render_sarif_html(_doc([_result()]))
    assert "does not record which edition" in html
    assert "2025 edition" not in html and "2026 edition" not in html


def test_the_edition_helpers_read_the_findings_not_a_constant():
    assert _editions_of([(_result(**{"owasp-edition": "2026"}), _RULE)]) == ["2026"]
    assert _editions_of([(_result(), _RULE)]) == []
    assert "2026 edition" in _edition_sentence([(_result(**{"owasp-edition": "2026"}), _RULE)])
