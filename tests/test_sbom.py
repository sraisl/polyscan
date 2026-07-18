"""Test the CycloneDX SBOM generator."""
from pathlib import Path

from polyscan.core.sbom import build_sbom, collect


def test_sbom_valid():
    bom = build_sbom(Path(__file__).parent.parent)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert "components" in bom
    for c in bom["components"]:
        assert c["purl"].startswith("pkg:")
        assert c["type"] == "library"


def test_sbom_dedup():
    comps = collect(Path(__file__).parent.parent)
    purls = [c["purl"] for c in comps]
    assert len(purls) == len(set(purls)), "purls must be unique"
