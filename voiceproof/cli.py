"""Command-line interface for VoiceProof."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from .core import VoiceProof, VoiceProofError
from .server import serve


def _load_secret(db_path: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("VOICEPROOF_SECRET")
    if env:
        return env
    if db_path == ":memory:":
        return secrets.token_hex(32)
    secret_file = Path(db_path + ".secret")
    if secret_file.exists():
        return secret_file.read_text(encoding="utf-8").strip()
    secret = secrets.token_hex(32)
    secret_file.write_text(secret, encoding="utf-8")
    try:
        secret_file.chmod(0o600)
    except OSError:
        pass
    return secret


def _vp(args) -> VoiceProof:
    return VoiceProof(
        db_path=args.db,
        secret=_load_secret(args.db, args.secret),
        threshold=args.threshold,
        token_ttl_seconds=args.token_ttl,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="voiceproof",
                                     description="Self-hosted signed payment approval.")
    parser.add_argument("--db", default="voiceproof.db")
    parser.add_argument("--secret", default=None,
                        help="HMAC secret (or VOICEPROOF_SECRET env / <db>.secret file)")
    parser.add_argument("--threshold", type=float, default=1000.0)
    parser.add_argument("--token-ttl", type=int, default=3600)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("add-approver", help="register an approver")
    p.add_argument("name")
    p.add_argument("--credential", default=None)

    p = sub.add_parser("create", help="create an approval request")
    p.add_argument("--amount", type=float, required=True)
    p.add_argument("--payee", required=True)
    p.add_argument("--requester", required=True)
    p.add_argument("--reason", default="")

    p = sub.add_parser("issue-token", help="issue a signed approval token")
    p.add_argument("request_id")
    p.add_argument("--approver", required=True)

    p = sub.add_parser("approve", help="approve via a signed token")
    p.add_argument("token")

    p = sub.add_parser("reject", help="reject via a signed token")
    p.add_argument("token")

    p = sub.add_parser("status", help="show a request")
    p.add_argument("request_id")

    p = sub.add_parser("audit", help="show the audit log")
    p.add_argument("request_id", nargs="?")

    p = sub.add_parser("serve", help="run the web UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)

    args = parser.parse_args(argv)
    vp = _vp(args)
    try:
        if args.command == "add-approver":
            result = vp.register_approver(args.name, args.credential)
            print(json.dumps(result))
        elif args.command == "create":
            rid = vp.create_request(args.amount, args.payee, args.requester, args.reason)
            print(json.dumps({"request_id": rid}))
        elif args.command == "issue-token":
            token = vp.issue_token(args.request_id, args.approver)
            print(json.dumps({"token": token, "url": f"/approve?token={token}"}))
        elif args.command == "approve":
            print(json.dumps(vp.approve_with_token(args.token), default=str))
        elif args.command == "reject":
            print(json.dumps(vp.reject_with_token(args.token), default=str))
        elif args.command == "status":
            print(json.dumps(vp.get_request(args.request_id), indent=2, default=str))
        elif args.command == "audit":
            print(json.dumps(vp.get_audit_log(args.request_id), indent=2, default=str))
        elif args.command == "serve":
            serve(vp, args.host, args.port)
        return 0
    except VoiceProofError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if args.command != "serve":
            vp.close()


if __name__ == "__main__":
    raise SystemExit(main())
