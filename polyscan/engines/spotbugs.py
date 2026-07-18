"""SpotBugs adapter — Java / Kotlin static analysis (incl. FindSecBugs security)."""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from polyscan.core.schema import EngineResult, Finding, Severity
from polyscan.engines.base import EngineAdapter

CLI = "java"

# bundled jars (download once, cache locally)
SPOTBUGS_HOME = Path("/root/.hermes/cache/spotbugs/dist/spotbugs-4.8.6")
SPOTBUGS_JAR = SPOTBUGS_HOME / "lib" / "spotbugs.jar"
FINDSECBUGS_JAR = Path("/root/.hermes/cache/spotbugs/findsecbugs.jar")


def _classpath() -> str:
    if SPOTBUGS_HOME.exists():
        jars = [str(SPOTBUGS_HOME / "lib" / "spotbugs.jar")]
        jars += [str(p) for p in (SPOTBUGS_HOME / "lib").glob("*.jar")]
        return ":".join(jars)
    return str(SPOTBUGS_JAR)

SEV_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "IGNORE": Severity.INFO,
}

# rough CWE hints for common FindSecBugs patterns
CWE_HINTS = {
    "SQL_INJECTION": "CWE-89",
    "XSS": "CWE-79",
    "PATH_TRAVERSAL": "CWE-22",
    "COMMAND_INJECTION": "CWE-78",
    "LDAP_INJECTION": "CWE-90",
    "XXE": "CWE-611",
    "WEAK_CIPHER": "CWE-327",
    "WEAK_HASH": "CWE-328",
    "HARD_CODE_PASSWORD": "CWE-798",
}


def _collect_sources(target: Path) -> list[Path]:
    exts = ("*.java", "*.kt")
    out = []
    for ext in exts:
        out.extend(target.rglob(ext))
    return out


def _compile(java_files: list[Path], out_dir: Path) -> bool:
    out_dir.mkdir(parents=True, exist_ok=True)
    # compile with classpath = spotbugs jar (for any provided deps it's fine)
    cmd = ["javac", "-d", str(out_dir)] + [str(f) for f in java_files]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return proc.returncode == 0


def run(target: Path) -> EngineResult:
    target = target.resolve()
    findings: list[Finding] = []
    errors: list[str] = []

    if not SPOTBUGS_JAR.exists():
        return EngineResult(
            engine="spotbugs",
            findings=[],
            errors=[f"spotbugs.jar missing at {SPOTBUGS_JAR}"],
            skipped=True,
        )

    sources = _collect_sources(target)
    if not sources:
        return EngineResult(engine="spotbugs", findings=[], errors=["no .java/.kt files"])

    classes_dir = target / ".polyscan_classes"
    compiled = _compile(sources, classes_dir)
    if not compiled:
        # still try to run on sources via spotbugs textui (it can accept dirs)
        errors.append("javac compile failed — scanning may be incomplete")

    xml_report = target / ".polyscan_spotbugs.xml"
    cmd = [
        "java", "-cp", _classpath(),
        "edu.umd.cs.findbugs.LaunchAppropriateUI",
        "-textui",
        "-pluginList", str(FINDSECBUGS_JAR),
        "-effort:max", "-xml:withMessages",
        "-output", str(xml_report),
        str(classes_dir if compiled else target),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=400)
    if not xml_report.exists():
        errors.append(proc.stderr[:400] or "spotbugs produced no report")
        _clean(target, classes_dir, xml_report)
        return EngineResult(engine="spotbugs", findings=[], errors=errors)

    try:
        root = ET.parse(xml_report).getroot()
        for bug in root.iter("BugInstance"):
            bug_type = bug.get("type", "UNKNOWN")
            severity = SEV_MAP.get(bug.get("priority"), Severity.MEDIUM)
            # priority 1=high,2=medium,3=low in spotbugs
            pr = bug.get("priority")
            if pr == "1":
                severity = Severity.HIGH
            elif pr == "2":
                severity = Severity.MEDIUM
            elif pr == "3":
                severity = Severity.LOW
            src = bug.find("Class/SourceLine") or bug.find("SourceLine")
            file_ = ""
            line = None
            if src is not None:
                file_ = src.get("sourcefile", src.get("classname", ""))
                line = src.get("start", src.get("lineNumber"))
                line = int(line) if line and line.isdigit() else None
            cwe = None
            for key in CWE_HINTS:
                if key in bug_type.upper():
                    cwe = CWE_HINTS[key]
                    break
            msg = bug.findtext("LongMessage") or bug_type
            findings.append(
                Finding(
                    engine="spotbugs",
                    rule_id=bug_type,
                    severity=severity,
                    language="java",
                    file=file_,
                    line=line,
                    message=msg,
                    cwe=cwe,
                )
            )
    except ET.ParseError as e:
        errors.append(f"xml parse error: {e}")

    _clean(target, classes_dir, xml_report)
    return EngineResult(engine="spotbugs", findings=findings, errors=errors)


def _clean(target: Path, *paths):
    for p in paths:
        if p.exists():
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink(missing_ok=True)
