"""Engine registry. Adapters live in semgrep.py / bandit.py / eslint.py / spotbugs.py."""
from polyscan.engines import semgrep, bandit, eslint, spotbugs

ENGINES = {
    "semgrep": semgrep,
    "bandit": bandit,
    "eslint": eslint,
    "spotbugs": spotbugs,
}
