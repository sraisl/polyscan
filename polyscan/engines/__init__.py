"""Engine registry. Adapters live in semgrep.py / bandit.py / eslint.py."""
from polyscan.engines import semgrep, bandit, eslint

ENGINES = {
    "semgrep": semgrep,
    "bandit": bandit,
    "eslint": eslint,
}
