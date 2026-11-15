"""VoiceProof core: store, signed one-time tokens, rules engine, audit log.

Standard library only. No external services.

Security idea: a payment is never approved because someone *sounded*
like the CEO on a call. Approval is proven by redeeming an HMAC-signed,
expiring, single-use token that was issued for one specific request and
one specific registered approver.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def hash_credential(credential: str) -> str:
    """Return ``salt$sha256(salt + credential)`` — never the plaintext."""
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + credential).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def verify_credential(stored: str, credential: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    candidate = hashlib.sha256((salt + credential).encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate, digest)


class VoiceProofError(Exception):
    """Base error for VoiceProof."""


class TokenError(VoiceProofError):
    """Malformed or bad-signature token."""


class TokenExpiredError(TokenError):
    """Token past its expiry."""


class TokenReplayError(TokenError):
    """Token already used (single-use violation)."""


class SelfApprovalError(VoiceProofError):
    """A requester tried to approve their own request."""


class DuplicateApprovalError(VoiceProofError):
    """Same approver tried to approve the same request twice."""


class NotFoundError(VoiceProofError):
    """Request or approver does not exist."""


class InvalidStateError(VoiceProofError):
    """Request is not pending (already approved / rejected)."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvers (
    name TEXT PRIMARY KEY,
    credential_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    amount REAL NOT NULL,
    payee TEXT NOT NULL,
    requester TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    required_approvals INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    approver TEXT NOT NULL,
    decision TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(request_id, approver)
);
CREATE TABLE IF NOT EXISTS tokens (
    jti TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    approver TEXT NOT NULL,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
"""


class VoiceProof:
    """Self-hosted payment-approval service.

    Parameters
    ----------
    db_path: SQLite path, or ``":memory:"`` (default) for tests.
    secret: HMAC signing secret. Generated if not supplied.
    threshold: amounts strictly *above* this need two distinct
        approvers; amounts at or below it need one.
    token_ttl_seconds: lifetime of a signed approval token.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        secret: str | None = None,
        threshold: float = 1000.0,
        token_ttl_seconds: int = 3600,
    ):
        self.db_path = db_path
        self.secret = secret if secret is not None else secrets.token_hex(32)
        self.threshold = float(threshold)
        self.token_ttl_seconds = int(token_ttl_seconds)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- audit ---------------------------------------------------------
    def _audit(self, request_id, actor: str, action: str, detail: str = "") -> None:
        # Append-only: this is the only code path that touches audit_log,
        # and it only ever INSERTs.
        self._conn.execute(
            "INSERT INTO audit_log (request_id, actor, action, detail, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (request_id, actor, action, detail, _utcnow()),
        )

    def get_audit_log(self, request_id: str | None = None) -> list[dict]:
        with self._lock:
            if request_id is None:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log ORDER BY id ASC"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log WHERE request_id = ? ORDER BY id ASC",
                    (request_id,),
                ).fetchall()
            return [dict(r) for r in rows]

    # -- approvers -----------------------------------------------------
    def register_approver(self, name: str, credential: str | None = None) -> dict:
        """Register an approver. Only a salted hash is stored at rest.

        Returns ``{"name": ..., "credential": <plaintext or None>}`` —
        the plaintext is returned only when it was generated here, so
        the caller can hand it to the approver once.
        """
        name = (name or "").strip()
        if not name:
            raise VoiceProofError("approver name is required")
        generated = credential is None
        if generated:
            credential = secrets.token_urlsafe(24)
        with self._lock:
            exists = self._conn.execute(
                "SELECT name FROM approvers WHERE name = ?", (name,)
            ).fetchone()
            if exists:
                raise VoiceProofError(f"approver {name!r} already registered")
            self._conn.execute(
                "INSERT INTO approvers (name, credential_hash, created_at)"
                " VALUES (?, ?, ?)",
                (name, hash_credential(credential), _utcnow()),
            )
            self._audit(None, name, "approver_registered", f"approver {name} registered")
            self._conn.commit()
        return {"name": name, "credential": credential if generated else None}

    def verify_approver_credential(self, name: str, credential: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT credential_hash FROM approvers WHERE name = ?", (name,)
            ).fetchone()
        if row is None:
            return False
        return verify_credential(row["credential_hash"], credential)

    def has_approver(self, name: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT name FROM approvers WHERE name = ?", (name,)
            ).fetchone()
        return row is not None

    # -- requests --------------------------------------------------------
    def required_approvals(self, amount: float) -> int:
        """Above threshold -> 2 distinct approvers; at/below -> 1."""
        return 2 if float(amount) > self.threshold else 1

    def create_request(self, amount, payee: str, requester: str, reason: str) -> str:
        amount = float(amount)
        if amount <= 0:
            raise VoiceProofError("amount must be positive")
        if not (payee or "").strip():
            raise VoiceProofError("payee is required")
        if not (requester or "").strip():
            raise VoiceProofError("requester is required")
        request_id = uuid.uuid4().hex[:16]
        needed = self.required_approvals(amount)
        with self._lock:
            self._conn.execute(
                "INSERT INTO requests (id, amount, payee, requester, reason,"
                " status, required_approvals, created_at)"
                " VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
                (request_id, amount, payee.strip(), requester.strip(),
                 reason or "", needed, _utcnow()),
            )
            self._audit(
                request_id, requester.strip(), "request_created",
                f"amount={amount} payee={payee.strip()} required_approvals={needed}",
            )
            self._conn.commit()
        return request_id

    def get_request(self, request_id: str) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM requests WHERE id = ?", (request_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"request {request_id!r} not found")
            result = dict(row)
            approvals = self._conn.execute(
                "SELECT approver, decision, created_at FROM approvals"
                " WHERE request_id = ? ORDER BY id ASC",
                (request_id,),
            ).fetchall()
            result["approvals"] = [dict(a) for a in approvals]
            result["approval_count"] = sum(
                1 for a in approvals if a["decision"] == "approve"
            )
            return result

    def list_requests(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM requests ORDER BY created_at ASC, id ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    # -- signed one-time tokens -------------------------------------------
    def _sign(self, payload_b64: str) -> str:
        sig = hmac.new(
            self.secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
        ).digest()
        return _b64encode(sig)

    def issue_token(self, request_id: str, approver: str) -> str:
        """Issue an HMAC-signed, expiring, single-use approval token."""
        with self._lock:
            req = self.get_request(request_id)  # raises NotFoundError
            if req["status"] != "pending":
                raise InvalidStateError(f"request is {req['status']}, not pending")
            if not self.has_approver(approver):
                raise NotFoundError(f"approver {approver!r} not registered")
            jti = uuid.uuid4().hex
            expires_at = time.time() + self.token_ttl_seconds
            payload = {
                "jti": jti,
                "rid": request_id,
                "approver": approver,
                "exp": int(expires_at),
                "purpose": "approval",
            }
            payload_b64 = _b64encode(
                json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            )
            token = f"{payload_b64}.{self._sign(payload_b64)}"
            self._conn.execute(
                "INSERT INTO tokens (jti, request_id, approver, expires_at, used, created_at)"
                " VALUES (?, ?, ?, ?, 0, ?)",
                (jti, request_id, approver, expires_at, _utcnow()),
            )
            self._audit(request_id, approver, "token_issued",
                        f"token jti={jti[:8]}… for approver {approver}")
            self._conn.commit()
            return token

    def _decode_and_verify_signature(self, token: str) -> dict:
        if not token or "." not in token:
            raise TokenError("malformed token")
        payload_b64, sig_b64 = token.rsplit(".", 1)
        expected = self._sign(payload_b64)
        if not hmac.compare_digest(expected, sig_b64):
            raise TokenError("bad token signature")
        try:
            payload = json.loads(_b64decode(payload_b64))
        except Exception as exc:  # noqa: BLE001 - surface as TokenError
            raise TokenError("undecodable token payload") from exc
        if payload.get("purpose") != "approval":
            raise TokenError("token purpose is not approval")
        return payload

    def peek_token(self, token: str) -> dict:
        """Verify a token without consuming it (for the approval page)."""
        payload = self._decode_and_verify_signature(token)
        if time.time() > float(payload["exp"]):
            raise TokenExpiredError("token has expired")
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tokens WHERE jti = ?", (payload["jti"],)
            ).fetchone()
            if row is None:
                raise TokenError("unknown token")
            if row["used"]:
                raise TokenReplayError("token already used")
        return payload

    def redeem_token(self, token: str, decision: str) -> dict:
        """Redeem a token once to approve or reject. Returns the request."""
        if decision not in ("approve", "reject"):
            raise VoiceProofError("decision must be 'approve' or 'reject'")
        payload = self._decode_and_verify_signature(token)
        request_id = payload["rid"]
        approver = payload["approver"]

        # Expiry: recorded in the audit log, then refused.
        if time.time() > float(payload["exp"]):
            with self._lock:
                self._audit(request_id, approver, "expire",
                            "expired token presented for redemption")
                self._conn.commit()
            raise TokenExpiredError("token has expired")

        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tokens WHERE jti = ?", (payload["jti"],)
            ).fetchone()
            if row is None:
                raise TokenError("unknown token")
            if row["used"]:
                self._audit(request_id, approver, "token_replay_rejected",
                            "single-use token presented a second time")
                self._conn.commit()
                raise TokenReplayError("token already used")

            req = self.get_request(request_id)
            if req["status"] != "pending":
                raise InvalidStateError(f"request is {req['status']}, not pending")

            # Self-approval is refused before the token is consumed.
            if approver == req["requester"]:
                self._audit(request_id, approver, "self_approval_rejected",
                            "requester attempted to approve own request")
                self._conn.commit()
                raise SelfApprovalError(
                    "a requester cannot approve their own request"
                )

            already = [a for a in req["approvals"] if a["approver"] == approver]
            if already:
                self._audit(request_id, approver, "duplicate_approval_rejected",
                            "approver already decided this request")
                self._conn.commit()
                raise DuplicateApprovalError(
                    "this approver has already decided this request"
                )

            # Consume the token first (single-use), then record the decision.
            self._conn.execute(
                "UPDATE tokens SET used = 1 WHERE jti = ?", (payload["jti"],)
            )
            self._conn.execute(
                "INSERT INTO approvals (request_id, approver, decision, created_at)"
                " VALUES (?, ?, ?, ?)",
                (request_id, approver, decision, _utcnow()),
            )
            self._audit(request_id, approver, decision,
                        f"approver {approver} chose {decision}")

            if decision == "reject":
                new_status = "rejected"
            else:
                count = req["approval_count"] + 1
                new_status = (
                    "approved" if count >= req["required_approvals"] else "pending"
                )
            if new_status != "pending":
                self._conn.execute(
                    "UPDATE requests SET status = ? WHERE id = ?",
                    (new_status, request_id),
                )
                self._audit(request_id, approver, f"request_{new_status}",
                            f"request reached terminal status {new_status}")
            self._conn.commit()
            return self.get_request(request_id)

    # Convenience aliases used by CLI / server wording.
    def approve_with_token(self, token: str) -> dict:
        return self.redeem_token(token, "approve")

    def reject_with_token(self, token: str) -> dict:
        return self.redeem_token(token, "reject")
