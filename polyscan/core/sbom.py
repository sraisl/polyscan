"""CycloneDX SBOM generator (lightweight, manifest-based).

Parses common dependency manifests in TARGET and emits a CycloneDX 1.5
JSON SBOM. No external deps required for the core formats we support.

Supported manifests:
  - pyproject.toml        (Python, PEP 621 [project] deps)
  - requirements.txt      (Python, pinned/unpinned)
  - package.json          (Node.js deps + devDeps)
  - pom.xml               (Maven, best-effort regex)
  - build.gradle          (Gradle, best-effort regex)
  - go.mod                (Go modules)
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

try:
    import xml.etree.ElementTree as ET
except ImportError:  # pragma: no cover
    ET = None

SBOM_SPEC = "http://cyclonedx.org/schema/bom/1.5"


def _comp(name: str, version: str | None, purl: str) -> dict:
    comp = {
        "type": "library",
        "name": name,
        "purl": purl,
    }
    if version:
        comp["version"] = version
    return comp


def _purl(ecosystem: str, name: str, version: str | None) -> str:
    v = f"@{version}" if version else ""
    ns, nm = (name.split("/", 1) + [name])[0], name.split("/", 1)[-1]
    if ecosystem == "pypi" and "/" in name:
        ns, nm = name.split("/", 1)
    return f"pkg:{ecosystem}/{ns}/{nm}{v}"


def _parse_pyproject(path: Path) -> list[tuple[str, str | None]]:
    out = []
    data = tomllib.loads(path.read_text())
    proj = data.get("project", {})
    for dep in proj.get("dependencies", []):
        out.append(_split_pin(dep))
    for sect in ("dependencies", "optional-dependencies"):
        if sect == "optional-dependencies":
            for grp in proj.get(sect, {}).values():
                for d in grp:
                    out.append(_split_pin(d))
    return out


def _split_pin(dep: str) -> tuple[str, str | None]:
    # strip markers / extras
    dep = re.split(r"[;\[]", dep)[0].strip()
    m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:[=~<>!]=?.*)?$", dep)
    if not m:
        return dep.strip(), None
    name = m.group(1)
    # extract version if pinned
    vm = re.search(r"(?:==|>=|<=|~=|!=)\s*([0-9][A-Za-z0-9.\-\+]*)$", dep)
    ver = vm.group(1) if vm else None
    return name, ver


def _parse_requirements(path: Path) -> list[tuple[str, str | None]]:
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        out.append(_split_pin(line))
    return out


def _parse_package_json(path: Path) -> list[tuple[str, str | None]]:
    out = []
    import json

    data = json.loads(path.read_text())
    for sect in ("dependencies", "devDependencies"):
        for name, ver in data.get(sect, {}).items():
            v = str(ver).lstrip("^~>=<")
            v = v if re.match(r"^[0-9]", v) else None
            out.append((name, v))
    return out


def _parse_pom(path: Path) -> list[tuple[str, str | None]]:
    out = []
    if ET is None:
        return out
    try:
        root = ET.fromstring(path.read_text())
    except ET.ParseError:
        return out
    ns = "{http://maven.apache.org/POM/4.0.0}"
    for dep in root.iter(f"{ns}dependency"):
        gid = dep.findtext(f"{ns}groupId")
        aid = dep.findtext(f"{ns}artifactId")
        ver = dep.findtext(f"{ns}version")
        if gid and aid:
            out.append((f"{gid}/{aid}", ver))
    return out


def _parse_gomod(path: Path) -> list[tuple[str, str | None]]:
    out = []
    text = path.read_text()
    for m in re.finditer(r"^(\S+)\s+v([0-9][^\s]*)", text, re.MULTILINE):
        # skip the module / go directives
        if m.group(1) in ("module", "go"):
            continue
        out.append((m.group(1), m.group(2)))
    return out


MANIFEST_PARSERS = {
    "pyproject.toml": ("pypi", _parse_pyproject),
    "requirements.txt": ("pypi", _parse_requirements),
    "package.json": ("npm", _parse_package_json),
    "pom.xml": ("maven", _parse_pom),
    "go.mod": ("golang", _parse_gomod),
}


def collect(target: Path) -> list[dict]:
    components = []
    seen = set()
    for name, (eco, parser) in MANIFEST_PARSERS.items():
        for path in target.rglob(name):
            # skip node_modules / venv / build dirs
            if any(p in path.parts for p in ("node_modules", ".venv", "venv", "dist")):
                continue
            try:
                for dep_name, ver in parser(path):
                    purl = _purl(eco, dep_name, ver)
                    if purl in seen:
                        continue
                    seen.add(purl)
                    components.append(_comp(dep_name, ver, purl))
            except Exception:
                continue
    return components


def build_sbom(target: Path) -> dict:
    components = collect(target)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:polyscan-" + str(abs(hash(str(target))) % 10**12),
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": target.name or "scanned-target",
                "purl": f"pkg:generic/{target.name or 'target'}",
            }
        },
        "components": components,
    }


def write_sbom(target: Path, out_path: Path) -> None:
    import json

    sbom = build_sbom(target)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sbom, indent=2))
