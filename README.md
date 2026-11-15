# voiceproof

Self-hosted payment approval that defeats deepfake / CEO-fraud by moving
approval **off voice and onto a signed channel**.

The fraud pattern is familiar: a finance employee gets a call (or a video
call) that sounds exactly like the CEO, asking for an urgent payment.
Voice is no longer proof of identity. VoiceProof never approves a payment
because of a voice at all — approval is proven by redeeming an
**HMAC-signed, expiring, single-use token** that was issued for one
specific request and one specific registered approver.

> **VoiceProof does NOT detect deepfakes.** It does not analyse audio or
> video. It removes approval from the voice channel to a signed one, so a
> convincing fake voice has nothing to approve with.

## Features

- **Approval requests** — amount, payee, requester, reason; stored in
  SQLite.
- **Registered approvers** — each approver has a credential that is
  stored **hashed at rest** (salted SHA-256, `salt$hash`); the plaintext
  is never written to the database.
- **Signed one-time approval links** — every approval/rejection is done
  by redeeming a token that is:
  - HMAC-SHA256 signed (tampering invalidates it),
  - expiring (configurable TTL, default 1 hour),
  - **single-use** — replaying the same token a second time fails.
- **Rules engine**
  - Amounts **above** a configurable threshold (default 1000) require
    **two distinct approvers**; amounts at or below the threshold need
    one.
  - The same approver can never count twice for one request.
  - **A requester cannot approve (or reject) their own request.**
  - A single rejection closes the request as `rejected`.
- **Append-only audit log** — every action is recorded with who / when /
  what: `request_created`, `token_issued`, `approve`, `reject`,
  `expire`, plus terminal and refused-attempt events
  (`request_approved`, `request_rejected`, `token_replay_rejected`,
  `self_approval_rejected`, `duplicate_approval_rejected`,
  `approver_registered`). The code only ever INSERTs into the audit
  table.
- **Minimal web UI** (`http.server`, no framework) — create a request,
  view request status, and an approval page behind the token link.
- **JSON API + CLI** for creating approvers / requests / tokens and for
  driving the whole flow from scripts or tests.
- **Standard library only** — `http.server` + `sqlite3` + `hmac`. No
  third-party runtime dependencies, no external services.

## Install

Python 3.11+ only. No third-party runtime dependencies — standard
library only (pytest is used for the tests).

```bash
git clone https://github.com/tahiryounas604/voiceproof.git
cd voiceproof
# optional: install as a command
pip install --break-system-packages .
```

## Usage

### Web UI

```bash
python3 voiceproof.py --db voiceproof.db --secret "change-me-long-random" serve --port 8000
# open http://127.0.0.1:8000/
```

1. Create a request on the home page (or via CLI / API below).
2. Register approvers and issue a token link for one of them.
3. Send the approver the link — `/approve?token=…` — over a channel you
   already trust (your internal chat, email, in person). **Not** as a
   follow-up to a voice call asking for it.
4. The approver opens the link, sees amount / payee / requester / reason,
   and clicks Approve or Reject. The token dies after that one use.

### CLI

```bash
# Register an approver (omit --credential to generate one; shown once)
python3 voiceproof.py --db vp.db add-approver alice

# Create a request (prints {"request_id": "..."})
python3 voiceproof.py --db vp.db create --amount 250 --payee "Vendor Ltd" \
    --requester dave --reason "invoice 42"

# Issue the signed one-time link for an approver
python3 voiceproof.py --db vp.db issue-token <request_id> --approver alice

# Redeem it (this is what the approval page does)
python3 voiceproof.py --db vp.db approve <token>

# Inspect
python3 voiceproof.py --db vp.db status <request_id>
python3 voiceproof.py --db vp.db audit <request_id>
```

If `--secret` is not given, the CLI reads `VOICEPROOF_SECRET` from the
environment, or a `<db>.secret` file it creates next to the database
(mode 0600). Keep that secret secret: anyone holding it can forge
approval tokens.

### JSON API

| Method | Path | Body / result |
|---|---|---|
| POST | `/api/approvers` | `{"name": "...", "credential": "..."}` → 201 |
| POST | `/api/requests` | `{"amount": 250, "payee": "...", "requester": "...", "reason": "..."}` → `{"request_id", "status", "required_approvals"}` |
| GET | `/api/requests/<id>` | full request incl. approvals |
| POST | `/api/tokens` | `{"request_id": "...", "approver": "..."}` → `{"token", "url"}` |
| POST | `/api/approve` | `{"token": "...", "decision": "approve"\|"reject"}` → `{"request_id", "status"}` |
| GET | `/health` | `{"status": "ok"}` |

## Architecture

```
voiceproof/
├── core.py     SQLite store, credential hashing, HMAC token
│               issue/peek/redeem, rules engine, append-only audit log
├── server.py   http.server handler: HTML pages + JSON API
└── cli.py      add-approver / create / issue-token / approve /
                reject / status / audit / serve
voiceproof.py   top-level entry-point shim
tests/          pytest suite (core rules + real HTTP smoke + CLI flow)
```

Data model (SQLite):

- `approvers(name, credential_hash, created_at)` — hash only, never plaintext
- `requests(id, amount, payee, requester, reason, status, required_approvals, created_at)`
- `approvals(request_id, approver, decision, created_at)` — `UNIQUE(request_id, approver)`
- `tokens(jti, request_id, approver, expires_at, used, created_at)` — `used` flips once, at redemption
- `audit_log(id, request_id, actor, action, detail, created_at)` — append-only

Token format: `base64url(payload_json) + "." + base64url(HMAC-SHA256(secret, payload_b64))`,
where the payload carries `jti`, request id, approver, expiry (`exp`)
and `purpose="approval"`. Redemption verifies, in order: signature →
known `jti` → expiry (audited as `expire`) → not used (replay audited
and refused) → request still pending → not self-approval → not a
duplicate approver. Only then is the token consumed and the decision
recorded.

## Tests

```bash
python3 -m pytest -q
```

26 tests, covering: token expiry rejection (including the audit entry),
token replay rejection on both approve and reject paths, tampered-token
rejection, the dual-approval rule (above-threshold request stays
`pending` after one approval, becomes `approved` after a second
*distinct* approver), the threshold boundary (at/below = 1 approver,
just above = 2, including a custom threshold), self-approval and
self-rejection refusal, audit-trail completeness and ordering,
approver credentials stored hashed (plaintext asserted absent from the
DB, for both supplied and generated credentials), request validation,
a real HTTP smoke test (server on an ephemeral port: register →
create → issue → approval page → approve → status `approved`), HTTP
replay failure, and the CLI end to end.

## HONEST LIMITS

- **VoiceProof does NOT detect deepfakes.** It does not inspect calls,
  audio, or video. It removes approval from the voice channel to a
  signed one — that is the whole defence. A fake voice can still *ask*;
  it just cannot *approve*.
- **The token link is a bearer credential.** Whoever opens it can decide
  as that approver. Deliver links over a channel you trust, keep the
  TTL short, and treat a forwarded link like a forwarded password.
- **The HMAC secret is the root of trust.** Anyone with the server
  secret can forge tokens for any approver. Protect `--secret` /
  `VOICEPROOF_SECRET` / the `<db>.secret` file accordingly; there is no
  key rotation in v0.1.
- **Approver credentials are salted SHA-256, not a slow KDF.** Fine for
  high-entropy generated credentials; if you let humans pick weak
  passwords, a leaked database is easier to crack than it should be.
  Argon2/bcrypt would need a third-party dependency, which v0.1 avoids
  by design (stdlib only).
- **No built-in TLS, user sessions, or delivery channel.** v0.1 serves
  plain HTTP via `http.server` for a trusted local network / behind
  your own reverse proxy; it does not email or message the link itself,
  and the web UI has no login — the token *is* the authorisation.
- **Single-node SQLite.** No multi-server deployment, no concurrent
  writer scaling beyond a small team, no backups — run it like the
  small internal tool it is.
- **Not penetration-tested or independently audited.** This is a v0.1
  reference implementation of the signed-approval pattern, tested by
  its own pytest suite only. Review it before putting real money
  behind it.

## Author

Tahir Younas — Tytechlabs — https://www.linkedin.com/in/tahiryounas604

## License

GPL-3.0 — see `LICENSE`.
