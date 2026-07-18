import os
import subprocess

# Bandit: B602 subprocess call with shell=True
def dangerous(cmd):
    subprocess.call(cmd, shell=True)

# Bandit: B307 eval
def run_user(code):
    return eval(code)

# Semgrep-ish: hardcoded secret (pseudo)
API_KEY = "sk-1234567890abcdef1234567890abcdef"
