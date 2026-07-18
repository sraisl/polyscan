"""SpotBugs asset resolver + lazy downloader.

JARs are not bundled in the wheel (license/size). They are fetched on
first use (or via `polyscan download-engines`) into a cache dir:

  - $POLYSCAN_CACHE/spotbugs   (default ~/.cache/polyscan/spotbugs)
  - legacy /root/.hermes/cache/spotbugs  (kept for backward compat)

This keeps the wheel small while making SpotBugs work out-of-the-box.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

SPOTBUGS_VERSION = "4.8.6"
FINDSECBUGS_VERSION = "1.13.0"

DIST_URL = (
    f"https://github.com/spotbugs/spotbugs/releases/download/"
    f"{SPOTBUGS_VERSION}/spotbugs-{SPOTBUGS_VERSION}.tgz"
)
FINDSECBUGS_URL = (
    f"https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/"
    f"findsecbugs-plugin/{FINDSECBUGS_VERSION}/"
    f"findsecbugs-plugin-{FINDSECBUGS_VERSION}.jar"
)


def cache_root() -> Path:
    env = os.environ.get("POLYSCAN_CACHE")
    if env:
        return Path(env)
    return Path.home() / ".cache" / "polyscan" / "spotbugs"


def spotbugs_home(root: Path | None = None) -> Path:
    root = root or cache_root()
    return root / "dist" / f"spotbugs-{SPOTBUGS_VERSION}"


def findsecbugs_jar(root: Path | None = None) -> Path:
    root = root or cache_root()
    return root / "findsecbugs.jar"


def classpath(home: Path) -> str:
    jars = [str(home / "lib" / "spotbugs.jar")]
    jars += [str(p) for p in (home / "lib").glob("*.jar")]
    return ":".join(jars)


def _legacy_root() -> Path | None:
    p = Path("/root/.hermes/cache/spotbugs")
    if (p / "dist" / f"spotbugs-{SPOTBUGS_VERSION}").exists():
        return p
    return None


def resolve() -> tuple[Path, Path, str] | None:
    """Return (spotbugs_home, findsecbugs_jar, classpath) or None if missing."""
    legacy = _legacy_root()
    root = legacy or cache_root()
    home = spotbugs_home(root)
    fsb = findsecbugs_jar(root)
    if home.exists() and fsb.exists():
        return home, fsb, classpath(home)
    return None


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  ↓ {url}", file=sys.stderr)
    urllib.request.urlretrieve(url, dest)


def ensure(force: bool = False) -> tuple[Path, Path, str] | None:
    """Download assets if missing. Returns resolved tuple or None on failure."""
    existing = resolve()
    if existing and not force:
        return existing

    root = cache_root()
    root.mkdir(parents=True, exist_ok=True)
    home = spotbugs_home(root)
    fsb = findsecbugs_jar(root)

    try:
        print("[polyscan] Fetching SpotBugs assets…", file=sys.stderr)
        _download(FINDSECBUGS_URL, fsb)

        tgz = root / "spotbugs.tgz"
        _download(DIST_URL, tgz)
        with tarfile.open(tgz) as tf:
            tf.extractall(root / "dist")
        tgz.unlink(missing_ok=True)

        # fix executable bit on spotbugs launcher
        launcher = home / "bin" / "spotbugs"
        if launcher.exists():
            launcher.chmod(0o755)
    except Exception as e:  # network / permission failure
        print(f"[polyscan] SpotBugs download failed: {e}", file=sys.stderr)
        print(
            "[polyscan] Install Java + run `polyscan download-engines`, "
            "or set POLYSCAN_CACHE to a dir with spotbugs-4.8.6/dist.",
            file=sys.stderr,
        )
        return None

    return home, fsb, classpath(home)
