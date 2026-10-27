"""SARIF results carry their OWASP category as a taxonomy reference, not only as properties.

WHY THIS FILE EXISTS. A finding said which OWASP category it belonged to only under
keys this tool documents (``properties.owasp_category``). SARIF 2.1.0 has a first-class
place for that: ``run.taxonomies`` declares the taxonomy once, and each result points
at its ``taxa`` entries, so consumers that understand SARIF can group and filter by
category without knowing our property names. These tests fail if the declaration or
the reference goes missing again — and they pin that the old property keys stay,
because removing them would break readers that already parse them.
"""

from __future__ import annotations

import json

from llmsectest.reporting.models import TestResult
from llmsectest.reporting.owasp_metadata import OWASP_LLM_CATEGORIES, get_owasp_category
from llmsectest.reporting.sarif_generator import (
    OWASP_TAXONOMY_GUID,
    OWASP_TAXONOMY_NAME,
    SARIFGenerator,
)


def _run(results):
    """Run the generator over ``results`` and return the parsed SARIF run."""
    generator = SARIFGenerator("llmsectest", "0.1.0", source_root=".")
    return json.loads(generator.generate(results))["runs"][0]


def _finding(markers):
    return TestResult(
        nodeid="…::test_probe[case]",
        location=("src/llmsectest/suite/test_probe.py", 18, "t"),
        outcome="failed",
        longrepr="Failed: the target complied",
        markers=markers,
        properties={"llmsec_finding": "the target complied"},
    )


def test_the_run_declares_the_owasp_taxonomy_with_all_categories():
    run = _run([_finding(["security", "owasp_llm01", "high"])])
    (taxonomy,) = run["taxonomies"]
    assert taxonomy["name"] == OWASP_TAXONOMY_NAME
    assert taxonomy["version"] == "2026"
    assert taxonomy["guid"] == OWASP_TAXONOMY_GUID
    expected_ids = [get_owasp_category(m).id for m in OWASP_LLM_CATEGORIES]
    assert [t["id"] for t in taxonomy["taxa"]] == expected_ids
    assert len(taxonomy["taxa"]) == 10
    for taxon in taxonomy["taxa"]:
        assert taxon["name"]
        assert taxon["shortDescription"]["text"]
        assert taxon["fullDescription"]["text"]


def test_a_finding_references_its_taxon_and_keeps_its_properties():
    result = _run([_finding(["security", "owasp_llm01", "high"])])["results"][0]
    assert result["taxa"] == [
        {
            "id": "LLM01",
            "toolComponent": {"name": OWASP_TAXONOMY_NAME, "guid": OWASP_TAXONOMY_GUID},
        }
    ]
    assert result["properties"]["owasp_category"] == "LLM01"
    assert result["properties"]["owasp_name"] == "Prompt Injection"
    assert result["properties"]["cwe_ids"] == ["CWE-77", "CWE-78", "CWE-94"]


def test_a_result_without_a_category_references_no_taxon():
    result = _run([_finding(["security", "high"])])["results"][0]
    assert "taxa" not in result
    assert "owasp_category" not in result["properties"]


def test_a_withstood_row_references_its_taxon():
    held = TestResult(
        nodeid="suite/test_probe.py::held",
        location=("suite/test_probe.py", 12, "held"),
        outcome="passed",
        markers=["owasp_llm01", "high"],
        properties={
            "llmsec_probe": "owasp_llm01",
            "llmsec_reply": "I am sorry, I cannot help with that.",
        },
    )
    (row,) = _run([held])["results"]
    assert row["kind"] == "pass"
    assert row["taxa"] == [
        {
            "id": "LLM01",
            "toolComponent": {"name": OWASP_TAXONOMY_NAME, "guid": OWASP_TAXONOMY_GUID},
        }
    ]
    assert row["properties"]["owasp_category"] == "LLM01"
