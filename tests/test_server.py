"""HTTP smoke + CLI tests: real server on an ephemeral port."""
import json
import threading
import urllib.request
import urllib.error

import pytest

from voiceproof import VoiceProof
from voiceproof.cli import main as cli_main
from voiceproof.server import make_server


@pytest.fixture()
def http_base():
    vp = VoiceProof(db_path=":memory:", secret="http-test-secret",
                    threshold=1000.0, token_ttl_seconds=3600)
    server = make_server(vp, host="127.0.0.1", port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", vp
    server.shutdown()
    server.server_close()
    vp.close()


def _request(method, url, data=None, form=False):
    if data is None:
        body = None
        headers = {}
    elif form:
        from urllib.parse import urlencode
        body = urlencode(data).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    else:
        body = json.dumps(data).encode()
        headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_http_smoke_full_flow(http_base):
    base, _vp = http_base
    # Register approver via API.
    status, body = _request("POST", f"{base}/api/approvers",
                            {"name": "alice", "credential": "alice-http-cred"})
    assert status == 201

    # Create a request via HTTP (JSON API).
    status, body = _request("POST", f"{base}/api/requests",
                            {"amount": 250, "payee": "Vendor Ltd",
                             "requester": "dave", "reason": "smoke test"})
    assert status == 201
    created = json.loads(body)
    rid = created["request_id"]
    assert created["status"] == "pending"

    # Status before approval.
    status, body = _request("GET", f"{base}/api/requests/{rid}")
    assert status == 200
    assert json.loads(body)["status"] == "pending"

    # Issue a token and approve via the token link flow.
    status, body = _request("POST", f"{base}/api/tokens",
                            {"request_id": rid, "approver": "alice"})
    assert status == 201
    token = json.loads(body)["token"]

    # The approval page renders (GET must not consume the token).
    status, body = _request("GET", f"{base}/approve?token={token}")
    assert status == 200
    assert "Approve payment?" in body

    # Approve via the token link (form POST, like the page's button).
    status, body = _request("POST", f"{base}/approve",
                            {"token": token, "decision": "approve"}, form=True)
    assert status == 200
    assert "approved" in body

    # Status changed to approved.
    status, body = _request("GET", f"{base}/api/requests/{rid}")
    assert status == 200
    assert json.loads(body)["status"] == "approved"

    # HTML status page agrees.
    status, body = _request("GET", f"{base}/requests/{rid}")
    assert status == 200
    assert "approved" in body


def test_http_create_request_via_form(http_base):
    base, _vp = http_base
    status, body = _request("POST", f"{base}/requests",
                            {"amount": "75", "payee": "Shop",
                             "requester": "dave", "reason": "form"}, form=True)
    assert status == 201
    assert "Request created" in body
    status, body = _request("GET", f"{base}/")
    assert status == 200
    assert "VoiceProof" in body


def test_http_replay_via_api_fails(http_base):
    base, _vp = http_base
    _request("POST", f"{base}/api/approvers",
             {"name": "alice", "credential": "cred"})
    _, body = _request("POST", f"{base}/api/requests",
                       {"amount": 10, "payee": "V", "requester": "dave",
                        "reason": "r"})
    rid = json.loads(body)["request_id"]
    _, body = _request("POST", f"{base}/api/tokens",
                       {"request_id": rid, "approver": "alice"})
    token = json.loads(body)["token"]
    status, _ = _request("POST", f"{base}/api/approve",
                         {"token": token, "decision": "approve"})
    assert status == 200
    status, body = _request("POST", f"{base}/api/approve",
                            {"token": token, "decision": "approve"})
    assert status == 400
    assert "already used" in body


def test_cli_flow(tmp_path, capsys):
    db = str(tmp_path / "cli.db")
    common = ["--db", db, "--secret", "cli-secret", "--threshold", "1000"]
    assert cli_main(common + ["add-approver", "alice",
                              "--credential", "cli-cred"]) == 0
    assert cli_main(common + ["create", "--amount", "42", "--payee", "Vendor",
                              "--requester", "dave", "--reason", "cli"]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    rid = json.loads(out[-1])["request_id"]
    assert cli_main(common + ["issue-token", rid, "--approver", "alice"]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    token = json.loads(out[-1])["token"]
    assert cli_main(common + ["approve", token]) == 0
    assert cli_main(common + ["status", rid]) == 0
    out = capsys.readouterr().out
    assert '"approved"' in out
    assert cli_main(common + ["audit", rid]) == 0
    out = capsys.readouterr().out
    assert "request_created" in out
    assert "approve" in out
