"""Hand a code fix to Devin.

Night Watch contains an attack in milliseconds; the permanent fix (revert the
backdoor, restore the safety check, add a regression test) is a coding task.
Night Watch writes that task and, if DEVIN_API_KEY is set, opens a Devin session
for it. Without a key it runs in dry-run mode and just returns the task.
"""
from __future__ import annotations

import json
import os
import urllib.request

from .models import Event, Signal

DEVIN_API = os.environ.get("DEVIN_API_URL", "https://api.devin.ai/v1/sessions")
# Where the vulnerable service actually lives. In the demo it is demo_bank/ in this repo.
TARGET_REPO = os.environ.get("NW_TARGET_REPO", "github.com/Saif-616/CIS-Hackathon")
TARGET_FILE = os.environ.get("NW_TARGET_FILE", "demo_bank/payments/transfer.py")


def build_fix_task(event: Event, signals: list[Signal]) -> str:
    findings = "\n".join(f"- {s.code}: {s.reason}" + (f"\n    line: {s.evidence}" if s.evidence else "")
                         for s in signals if s.evidence or s.code in {"UNREVIEWED_PUSH"})
    return (
        f"Night Watch blocked commit {event.id} to {event.target} by {event.identity_id}.\n"
        f"Repository: {TARGET_REPO} (branch main). The malicious code is live in {TARGET_FILE}.\n"
        "This is a hackathon demo: the service, the PayLink secret and the hosts are fictional, "
        "so no real key needs rotating and no history rewrite or force-push is wanted.\n\n"
        f"Findings:\n{findings}\n\n"
        "Please:\n"
        f"1. In {TARGET_FILE}, remove the hard-coded IBAN bypass, the hard-coded secret and the "
        "outbound net.post call. Restore, before rail.send(req): the daily limit check "
        "(raise LimitExceeded), aml.screen(req.payee_iban) and audit.log(\"transfer\", req.id, req.amount).\n"
        "2. Read any partner secret from an environment variable instead of the code.\n"
        "3. Add demo_bank/tests/test_transfer_security.py with regression tests that fail if any "
        "check, the audit log or the bypass comes back, and that assert no outbound HTTP call is made.\n"
        "4. Add a CODEOWNERS file requiring review for demo_bank/payments/.\n"
        "5. Run `python3 -m pytest -q tests demo_bank/tests` and "
        "`git diff origin/main...HEAD -- demo_bank/payments | python3 -m nightwatch.scan`; both must pass.\n"
        f"6. Open a pull request titled \"Remediate backdoor {event.id} (found by Night Watch)\". "
        "In the description, list the manual follow-ups for a real incident: rotate the key, "
        "lock the committer's account, block the egress host, require 2 approvals on main."
    )


def send_to_devin(task: str, timeout: float = 10) -> dict:
    key = os.environ.get("DEVIN_API_KEY")
    if not key:
        return {"status": "dry_run", "task": task}
    req = urllib.request.Request(
        DEVIN_API, method="POST",
        data=json.dumps({"prompt": task, "title": "Night Watch: remediate blocked commit",
                         "tags": ["night-watch", "security"]}).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read() or b"{}")
        return {"status": "sent", "session": body.get("url"), "session_id": body.get("session_id"),
                "task": task}
    except Exception as exc:  # the demo must never crash on a network error
        return {"status": "error", "error": str(exc), "task": task}
