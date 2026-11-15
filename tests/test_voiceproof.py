"""Core tests: tokens, rules engine, self-approval, audit, credential hashing."""
import sqlite3
import time

import pytest

from voiceproof import (
    DuplicateApprovalError,
    SelfApprovalError,
    TokenExpiredError,
    TokenReplayError,
    VoiceProof,
)
from voiceproof.core import TokenError


def _create(vp, amount=100.0, requester="dave"):
    return vp.create_request(amount, payee="Vendor Ltd", requester=requester,
                             reason="invoice 42")


# -- token expiry ---------------------------------------------------------

def test_token_expiry_rejection():
    vp = VoiceProof(db_path=":memory:", secret="s3cret", threshold=1000.0,
                    token_ttl_seconds=-10)  # already expired at issue time
    try:
        vp.register_approver("alice", credential="cred-a")
        rid = vp.create_request(50, "Vendor", "dave", "test")
        token = vp.issue_token(rid, "alice")
        with pytest.raises(TokenExpiredError):
            vp.approve_with_token(token)
        # Request must still be pending — an expired token approves nothing.
        assert vp.get_request(rid)["status"] == "pending"
        # Expiry is audited.
        actions = [e["action"] for e in vp.get_audit_log(rid)]
        assert "expire" in actions
    finally:
        vp.close()


def test_token_expiry_with_short_ttl(monkeypatch):
    vp = VoiceProof(db_path=":memory:", secret="s3cret", threshold=1000.0,
                    token_ttl_seconds=60)
    try:
        vp.register_approver("alice", credential="cred-a")
        rid = vp.create_request(50, "Vendor", "dave", "test")
        token = vp.issue_token(rid, "alice")
        real_time = time.time
        monkeypatch.setattr(time, "time", lambda: real_time() + 3600)
        with pytest.raises(TokenExpiredError):
            vp.peek_token(token)
    finally:
        vp.close()


# -- token replay -----------------------------------------------------------

def test_token_replay_rejection(vp):
    rid = _create(vp)
    token = vp.issue_token(rid, "alice")
    result = vp.approve_with_token(token)
    assert result["status"] == "approved"
    with pytest.raises(TokenReplayError):
        vp.approve_with_token(token)


def test_token_replay_rejection_on_reject_path(vp):
    rid = _create(vp)
    token = vp.issue_token(rid, "alice")
    vp.reject_with_token(token)
    assert vp.get_request(rid)["status"] == "rejected"
    with pytest.raises(TokenReplayError):
        vp.reject_with_token(token)


def test_tampered_token_rejected(vp):
    rid = _create(vp)
    token = vp.issue_token(rid, "alice")
    tampered = token[:-3] + ("AAA" if not token.endswith("AAA") else "BBB")
    with pytest.raises(TokenError):
        vp.approve_with_token(tampered)


# -- dual approval / threshold ----------------------------------------------

def test_dual_approval_rule_above_threshold(vp):
    rid = _create(vp, amount=5000.0)
    assert vp.get_request(rid)["required_approvals"] == 2
    token1 = vp.issue_token(rid, "alice")
    after_one = vp.approve_with_token(token1)
    assert after_one["status"] == "pending"  # NOT approved after only one
    assert after_one["approval_count"] == 1
    token2 = vp.issue_token(rid, "bob")
    after_two = vp.approve_with_token(token2)
    assert after_two["status"] == "approved"
    assert after_two["approval_count"] == 2


def test_same_approver_cannot_count_twice(vp):
    rid = _create(vp, amount=5000.0)
    vp.approve_with_token(vp.issue_token(rid, "alice"))
    with pytest.raises(DuplicateApprovalError):
        vp.approve_with_token(vp.issue_token(rid, "alice"))
    assert vp.get_request(rid)["status"] == "pending"


def test_threshold_boundary_at_and_below(vp):
    # At threshold -> 1 approval suffices.
    assert vp.required_approvals(1000.0) == 1
    assert vp.required_approvals(999.99) == 1
    assert vp.required_approvals(0.01) == 1
    rid = _create(vp, amount=1000.0)
    result = vp.approve_with_token(vp.issue_token(rid, "alice"))
    assert result["status"] == "approved"


def test_threshold_boundary_just_above(vp):
    assert vp.required_approvals(1000.01) == 2
    assert vp.required_approvals(1001.0) == 2
    rid = _create(vp, amount=1000.01)
    result = vp.approve_with_token(vp.issue_token(rid, "alice"))
    assert result["status"] == "pending"


def test_custom_threshold():
    vp = VoiceProof(db_path=":memory:", secret="x", threshold=100.0)
    try:
        assert vp.required_approvals(100.0) == 1
        assert vp.required_approvals(100.01) == 2
    finally:
        vp.close()


def test_single_approval_below_threshold(vp):
    rid = _create(vp, amount=10.0)
    result = vp.approve_with_token(vp.issue_token(rid, "bob"))
    assert result["status"] == "approved"


def test_reject_is_terminal(vp):
    rid = _create(vp, amount=5000.0)
    vp.reject_with_token(vp.issue_token(rid, "alice"))
    assert vp.get_request(rid)["status"] == "rejected"


# -- self-approval ------------------------------------------------------------

def test_self_approval_rejection(vp):
    # 'dave' is the requester; register dave as an approver too, so the
    # only thing that can stop him is the self-approval rule itself.
    vp.register_approver("dave", credential="dave-credential-000")
    rid = _create(vp, requester="dave")
    token = vp.issue_token(rid, "dave")
    with pytest.raises(SelfApprovalError):
        vp.approve_with_token(token)
    assert vp.get_request(rid)["status"] == "pending"
    actions = [e["action"] for e in vp.get_audit_log(rid)]
    assert "self_approval_rejected" in actions


def test_self_rejection_also_blocked(vp):
    vp.register_approver("dave", credential="dave-credential-000")
    rid = _create(vp, requester="dave")
    with pytest.raises(SelfApprovalError):
        vp.reject_with_token(vp.issue_token(rid, "dave"))


def test_other_approver_can_approve_after_self_attempt(vp):
    vp.register_approver("dave", credential="dave-credential-000")
    rid = _create(vp, requester="dave")
    with pytest.raises(SelfApprovalError):
        vp.approve_with_token(vp.issue_token(rid, "dave"))
    result = vp.approve_with_token(vp.issue_token(rid, "alice"))
    assert result["status"] == "approved"


# -- audit trail ----------------------------------------------------------------

def test_audit_trail_completeness_and_order(vp):
    rid = _create(vp, amount=5000.0)
    token1 = vp.issue_token(rid, "alice")
    vp.approve_with_token(token1)
    token2 = vp.issue_token(rid, "bob")
    vp.approve_with_token(token2)

    log = vp.get_audit_log(rid)
    actions = [e["action"] for e in log]
    # Every spec action is recorded, in order.
    assert actions[0] == "request_created"
    assert actions[1] == "token_issued"
    assert actions[2] == "approve"
    assert actions[3] == "token_issued"
    assert actions[4] == "approve"
    assert actions[5] == "request_approved"
    # Who / when / what are present on every row.
    for entry in log:
        assert entry["actor"]
        assert entry["created_at"]
        assert entry["request_id"] == rid
    assert log[2]["actor"] == "alice"
    assert log[4]["actor"] == "bob"
    # IDs are monotonically increasing (append-only order).
    ids = [e["id"] for e in log]
    assert ids == sorted(ids)


def test_audit_records_reject(vp):
    rid = _create(vp)
    vp.reject_with_token(vp.issue_token(rid, "alice"))
    actions = [e["action"] for e in vp.get_audit_log(rid)]
    assert actions == ["request_created", "token_issued", "reject", "request_rejected"]


# -- approver credential hashing --------------------------------------------------

def test_approver_token_stored_hashed(tmp_path):
    db = str(tmp_path / "vp.db")
    vp = VoiceProof(db_path=db, secret="hash-test-secret")
    plaintext = "super-secret-approver-credential-xyz"
    try:
        vp.register_approver("alice", credential=plaintext)
    finally:
        vp.close()
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("SELECT name, credential_hash FROM approvers").fetchall()
        all_rows = conn.execute("SELECT * FROM approvers").fetchall()
    finally:
        conn.close()
    assert len(rows) == 1
    stored = rows[0][1]
    assert stored != plaintext
    assert plaintext not in stored
    # Plaintext must not appear anywhere in the approvers table.
    assert plaintext not in repr(all_rows)
    # And verification still works with the plaintext.
    vp2 = VoiceProof(db_path=db, secret="hash-test-secret")
    try:
        assert vp2.verify_approver_credential("alice", plaintext) is True
        assert vp2.verify_approver_credential("alice", "wrong") is False
    finally:
        vp2.close()


def test_generated_credential_also_hashed(tmp_path):
    db = str(tmp_path / "vp2.db")
    vp = VoiceProof(db_path=db, secret="s")
    try:
        result = vp.register_approver("erin")
        generated = result["credential"]
        assert generated  # returned once so it can be handed over
        assert vp.verify_approver_credential("erin", generated) is True
    finally:
        vp.close()
    conn = sqlite3.connect(db)
    try:
        stored = conn.execute(
            "SELECT credential_hash FROM approvers WHERE name='erin'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert generated not in stored


# -- misc validation ---------------------------------------------------------------

def test_create_request_validation(vp):
    with pytest.raises(Exception):
        vp.create_request(0, "Vendor", "dave", "zero amount")
    with pytest.raises(Exception):
        vp.create_request(-5, "Vendor", "dave", "negative")
    with pytest.raises(Exception):
        vp.create_request(10, "", "dave", "no payee")


def test_issue_token_unknown_approver(vp):
    rid = _create(vp)
    with pytest.raises(Exception):
        vp.issue_token(rid, "nobody")


def test_request_fields_roundtrip(vp):
    rid = vp.create_request(250.5, "ACME Corp", "dave", "Q3 licences")
    req = vp.get_request(rid)
    assert req["amount"] == 250.5
    assert req["payee"] == "ACME Corp"
    assert req["requester"] == "dave"
    assert req["reason"] == "Q3 licences"
    assert req["status"] == "pending"
