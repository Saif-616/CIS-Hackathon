"""End-to-end: every scenario gets the outcome we demo."""
from nightwatch import Action, NightWatch
from nightwatch.simulator import SCENARIOS, demo_identities


def run(name):
    nw = NightWatch(demo_identities())
    return nw, [nw.process(e) for _, e in SCENARIOS[name][1]()]


def test_normal_day_has_no_false_positives():
    _, ds = run("normal")
    assert all(d.action is Action.ALLOW for d in ds)


def test_rail_drain_blocked_on_first_payment_and_nothing_lost():
    nw, ds = run("drain")
    assert ds[0].action is Action.BLOCK
    assert all(d.action is Action.BLOCK for d in ds)
    assert nw.ledger.lost_aed == 0
    nw.respond(ds[0].event.id, confirmed_attack=True)
    assert nw.ledger.protected_aed == 512_000
    assert nw.ledger.held_aed == 0


def test_backdoor_commit_blocked_deploy_refused_and_devin_task_written():
    nw, ds = run("commit")
    commit, deploy = ds
    assert commit.action is Action.BLOCK
    codes = {s.code for s in commit.signals}
    assert {"HARDCODED_BYPASS", "SAFETY_CHECK_REMOVED", "SECRET_IN_CODE", "NEW_EGRESS"} <= codes
    assert commit.fix_task and "regression tests" in commit.fix_task
    assert "demo_bank/payments/transfer.py" in commit.fix_task
    assert deploy.action is Action.BLOCK
    assert any(s.code == "QUARANTINED_COMMIT" for s in deploy.signals)


def test_exfiltration_killed_and_rows_protected():
    nw, ds = run("exfil")
    assert ds[0].action is Action.BLOCK
    assert nw.ledger.protected_rows == 3_300_000
    assert nw.ledger.leaked_rows == 0


def test_false_positive_release_restores_access():
    nw, ds = run("drain")
    steps = nw.respond(ds[0].event.id, confirmed_attack=False)
    assert "false positive" in steps[0].lower()
    assert not nw.state["key-paylink"].revoked


def test_decisions_are_fast():
    _, ds = run("drain")
    assert max(d.latency_ms for d in ds) < 50
