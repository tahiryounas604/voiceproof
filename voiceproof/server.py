"""Minimal web UI + JSON API for VoiceProof, via http.server (stdlib)."""
from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .core import VoiceProof, VoiceProofError

_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>VoiceProof</title></head>
<body>
<h1>VoiceProof</h1>
<p>Payment approval on a <strong>signed channel</strong> — never on a voice call.
VoiceProof does not detect deepfakes; it removes approval from the voice
channel entirely.</p>
<h2>Create an approval request</h2>
<form method="post" action="/requests">
<label>Amount <input name="amount" required></label><br>
<label>Payee <input name="payee" required></label><br>
<label>Requester <input name="requester" required></label><br>
<label>Reason <input name="reason"></label><br>
<button type="submit">Create request</button>
</form>
<h2>Requests</h2>
<ul>{items}</ul>
</body></html>"""


def _esc(value) -> str:
    return html.escape(str(value))


def make_handler(vp: VoiceProof):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep test output clean
            pass

        # -- helpers ---------------------------------------------------
        def _send(self, code, body, content_type="text/html; charset=utf-8"):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj), "application/json")

        def _error_json(self, code, exc):
            self._json(code, {"error": str(exc)})

        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            ctype = self.headers.get("Content-Type") or ""
            if "application/json" in ctype:
                return json.loads(raw.decode("utf-8") or "{}")
            form = parse_qs(raw.decode("utf-8"))
            return {k: v[0] for k, v in form.items()}

        # -- GET ---------------------------------------------------------
        def do_GET(self):  # noqa: N802 (http.server API)
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            try:
                if path == "/":
                    items = "".join(
                        f'<li><a href="/requests/{_esc(r["id"])}">{_esc(r["id"])}</a>'
                        f' — {_esc(r["amount"])} to {_esc(r["payee"])}'
                        f' [{_esc(r["status"])}]</li>'
                        for r in vp.list_requests()
                    ) or "<li>No requests yet.</li>"
                    self._send(200, _PAGE.format(items=items))
                elif path.startswith("/api/requests/"):
                    req = vp.get_request(path.rsplit("/", 1)[1])
                    self._json(200, req)
                elif path.startswith("/requests/"):
                    req = vp.get_request(path.rsplit("/", 1)[1])
                    self._send(
                        200,
                        "<!doctype html><html><body>"
                        f"<h1>Request {_esc(req['id'])}</h1>"
                        f"<p>Amount: {_esc(req['amount'])}<br>"
                        f"Payee: {_esc(req['payee'])}<br>"
                        f"Requester: {_esc(req['requester'])}<br>"
                        f"Reason: {_esc(req['reason'])}<br>"
                        f"Status: <strong>{_esc(req['status'])}</strong><br>"
                        f"Approvals: {_esc(req['approval_count'])}"
                        f" of {_esc(req['required_approvals'])} required</p>"
                        '<p><a href="/">Back</a></p></body></html>',
                    )
                elif path == "/approve":
                    token = (query.get("token") or [""])[0]
                    payload = vp.peek_token(token)
                    req = vp.get_request(payload["rid"])
                    self._send(
                        200,
                        "<!doctype html><html><body>"
                        "<h1>Approve payment?</h1>"
                        f"<p>Amount: {_esc(req['amount'])}<br>"
                        f"Payee: {_esc(req['payee'])}<br>"
                        f"Requester: {_esc(req['requester'])}<br>"
                        f"Reason: {_esc(req['reason'])}<br>"
                        f"Approver: {_esc(payload['approver'])}</p>"
                        '<form method="post" action="/approve">'
                        f'<input type="hidden" name="token" value="{_esc(token)}">'
                        '<button name="decision" value="approve" type="submit">Approve</button>'
                        '<button name="decision" value="reject" type="submit">Reject</button>'
                        "</form></body></html>",
                    )
                elif path == "/health":
                    self._json(200, {"status": "ok"})
                else:
                    self._send(404, "not found", "text/plain; charset=utf-8")
            except VoiceProofError as exc:
                if path.startswith("/api/"):
                    self._error_json(400, exc)
                else:
                    self._send(400, f"<!doctype html><html><body><h1>Error</h1>"
                                    f"<p>{_esc(exc)}</p></body></html>")
            except Exception as exc:  # noqa: BLE001
                self._send(500, f"internal error: {_esc(exc)}", "text/plain")

        # -- POST --------------------------------------------------------
        def do_POST(self):  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                data = self._read_body()
                if path == "/api/approvers":
                    result = vp.register_approver(
                        data.get("name", ""), data.get("credential") or None
                    )
                    out = {"name": result["name"]}
                    if result["credential"]:
                        out["credential"] = result["credential"]
                    self._json(201, out)
                elif path in ("/api/requests", "/requests"):
                    request_id = vp.create_request(
                        float(data.get("amount", 0)),
                        data.get("payee", ""),
                        data.get("requester", ""),
                        data.get("reason", ""),
                    )
                    if path.startswith("/api/"):
                        req = vp.get_request(request_id)
                        self._json(201, {"request_id": request_id,
                                         "status": req["status"],
                                         "required_approvals": req["required_approvals"]})
                    else:
                        self._send(
                            201,
                            "<!doctype html><html><body>"
                            f"<h1>Request created</h1><p>ID: {_esc(request_id)}</p>"
                            f'<p><a href="/requests/{_esc(request_id)}">View status</a></p>'
                            "</body></html>",
                        )
                elif path == "/api/tokens":
                    token = vp.issue_token(data.get("request_id", ""),
                                           data.get("approver", ""))
                    self._json(201, {"token": token,
                                     "url": f"/approve?token={token}"})
                elif path in ("/api/approve", "/approve"):
                    req = vp.redeem_token(data.get("token", ""),
                                          data.get("decision", "approve"))
                    if path.startswith("/api/"):
                        self._json(200, {"request_id": req["id"],
                                         "status": req["status"]})
                    else:
                        self._send(
                            200,
                            "<!doctype html><html><body>"
                            f"<h1>Decision recorded</h1>"
                            f"<p>Request {_esc(req['id'])} is now "
                            f"<strong>{_esc(req['status'])}</strong>.</p>"
                            "</body></html>",
                        )
                else:
                    self._send(404, "not found", "text/plain; charset=utf-8")
            except VoiceProofError as exc:
                if path.startswith("/api/"):
                    self._error_json(400, exc)
                else:
                    self._send(400, f"<!doctype html><html><body><h1>Error</h1>"
                                    f"<p>{_esc(exc)}</p></body></html>")
            except Exception as exc:  # noqa: BLE001
                if path.startswith("/api/"):
                    self._error_json(500, exc)
                else:
                    self._send(500, f"internal error: {_esc(exc)}", "text/plain")

    return Handler


def make_server(vp: VoiceProof, host: str = "127.0.0.1", port: int = 8000):
    return ThreadingHTTPServer((host, port), make_handler(vp))


def serve(vp: VoiceProof, host: str = "127.0.0.1", port: int = 8000) -> None:
    server = make_server(vp, host, port)
    print(f"VoiceProof listening on http://{host}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
