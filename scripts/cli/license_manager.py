#!/usr/bin/env python3
"""
license_manager.py — Kagura license management tool.

4.6.14: Generates, validates, and revokes time-limited license tokens for
commercial distribution of kagura-protected binaries.

License token format (Base64url-encoded JSON payload + HMAC-SHA256 signature):
    <base64url(payload)>.<base64url(signature)>

Payload fields:
    licensee    Customer / app identifier
    product     "kagura" (fixed)
    version     Minimum kagura version required
    features    List of allowed passes (e.g. ["fla","bcf","str"])
    issued_at   Unix timestamp (int)
    expires_at  Unix timestamp (int) or 0 = never
    build_limit Max number of protected builds (0 = unlimited)
    build_count Current build count (maintained in license DB)
    token_id    Unique token UUID

Usage:
    # Generate a license
    python3 license_manager.py generate \\
        --licensee "Acme Corp" --features fla,bcf,str \\
        --days 365 --build-limit 10000

    # Validate a token (check signature + expiry)
    python3 license_manager.py validate --token <token>

    # List active licenses in the DB
    python3 license_manager.py list [--db license.db]

    # Increment build count (call from CI after a protected build)
    python3 license_manager.py record-build --token <token> [--db license.db]

    # Revoke a license
    python3 license_manager.py revoke --token-id <uuid> [--db license.db]

Environment:
    KAGURA_LICENSE_SECRET   HMAC signing secret (required for generate/validate)
    KAGURA_LICENSE_TOKEN    Default token for validate/record-build
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import time
import uuid
from typing import Optional

DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "license.db")
PRODUCT = "kagura"
MIN_VERSION = "4.6.14"


# ---- Helpers ---------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _sign(payload_b64: str, secret: str) -> str:
    sig = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).digest()
    return _b64url_encode(sig)


def _get_secret() -> str:
    secret = os.environ.get("KAGURA_LICENSE_SECRET", "")
    if not secret:
        print("ERROR: KAGURA_LICENSE_SECRET not set", file=sys.stderr)
        sys.exit(1)
    return secret


# ---- Token operations ------------------------------------------------------

def generate_token(
    licensee: str,
    features: list,
    days: int,
    build_limit: int,
    secret: str,
) -> str:
    now = int(time.time())
    payload = {
        "licensee":    licensee,
        "product":     PRODUCT,
        "version":     MIN_VERSION,
        "features":    features,
        "issued_at":   now,
        "expires_at":  now + days * 86400 if days > 0 else 0,
        "build_limit": build_limit,
        "build_count": 0,
        "token_id":    str(uuid.uuid4()),
    }
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _sign(payload_b64, secret)
    return f"{payload_b64}.{sig}"


def decode_token(token: str) -> dict:
    """Decode without verifying signature."""
    parts = token.split(".")
    if len(parts) != 2:
        raise ValueError("Malformed token (expected payload.signature)")
    payload = json.loads(_b64url_decode(parts[0]))
    return payload


def verify_token(token: str, secret: str) -> dict:
    """Verify HMAC signature and expiry. Returns payload on success."""
    parts = token.split(".")
    if len(parts) != 2:
        raise ValueError("Malformed token")
    payload_b64, provided_sig = parts
    expected_sig = _sign(payload_b64, secret)
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise ValueError("Invalid token signature")
    payload = json.loads(_b64url_decode(payload_b64))
    exp = payload.get("expires_at", 0)
    if exp and int(time.time()) > exp:
        raise ValueError(f"Token expired at {exp}")
    return payload


# ---- SQLite license DB -----------------------------------------------------

def open_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            token_id    TEXT PRIMARY KEY,
            licensee    TEXT,
            features    TEXT,
            issued_at   INTEGER,
            expires_at  INTEGER,
            build_limit INTEGER,
            build_count INTEGER DEFAULT 0,
            revoked     INTEGER DEFAULT 0,
            token       TEXT
        )
    """)
    conn.commit()
    return conn


def db_insert(conn: sqlite3.Connection, payload: dict, token: str) -> None:
    conn.execute("""
        INSERT OR REPLACE INTO licenses
            (token_id, licensee, features, issued_at, expires_at,
             build_limit, build_count, revoked, token)
        VALUES (?,?,?,?,?,?,?,0,?)
    """, (
        payload["token_id"],
        payload["licensee"],
        json.dumps(payload["features"]),
        payload["issued_at"],
        payload["expires_at"],
        payload["build_limit"],
        0,
        token,
    ))
    conn.commit()


def db_increment_build(conn: sqlite3.Connection, token_id: str) -> int:
    """Increment build_count; return new count or -1 if limit exceeded."""
    row = conn.execute(
        "SELECT build_count, build_limit, revoked FROM licenses WHERE token_id=?",
        (token_id,)
    ).fetchone()
    if not row:
        raise ValueError(f"Token ID {token_id} not in DB")
    count, limit, revoked = row
    if revoked:
        raise ValueError("License has been revoked")
    if limit > 0 and count >= limit:
        return -1
    new_count = count + 1
    conn.execute(
        "UPDATE licenses SET build_count=? WHERE token_id=?",
        (new_count, token_id)
    )
    conn.commit()
    return new_count


def db_revoke(conn: sqlite3.Connection, token_id: str) -> None:
    conn.execute(
        "UPDATE licenses SET revoked=1 WHERE token_id=?", (token_id,)
    )
    conn.commit()


def db_list(conn: sqlite3.Connection) -> list:
    rows = conn.execute("""
        SELECT token_id, licensee, features, issued_at, expires_at,
               build_limit, build_count, revoked
        FROM licenses ORDER BY issued_at DESC
    """).fetchall()
    result = []
    for r in rows:
        result.append({
            "token_id":    r[0],
            "licensee":    r[1],
            "features":    json.loads(r[2]),
            "issued_at":   r[3],
            "expires_at":  r[4],
            "build_limit": r[5],
            "build_count": r[6],
            "revoked":     bool(r[7]),
            "status":      "REVOKED" if r[7] else (
                           "EXPIRED" if r[4] and int(time.time()) > r[4] else
                           "ACTIVE"),
        })
    return result


# ---- CLI -------------------------------------------------------------------

def cmd_generate(args) -> None:
    secret = _get_secret()
    features = [f.strip() for f in args.features.split(",") if f.strip()]
    token = generate_token(args.licensee, features, args.days,
                           args.build_limit, secret)
    payload = decode_token(token)

    conn = open_db(args.db)
    db_insert(conn, payload, token)
    conn.close()

    result = {
        "token":      token,
        "token_id":   payload["token_id"],
        "licensee":   payload["licensee"],
        "features":   payload["features"],
        "issued_at":  payload["issued_at"],
        "expires_at": payload["expires_at"],
        "build_limit": payload["build_limit"],
    }
    print(json.dumps(result, indent=2))


def cmd_validate(args) -> None:
    secret = _get_secret()
    token = args.token or os.environ.get("KAGURA_LICENSE_TOKEN", "")
    if not token:
        print("ERROR: --token or KAGURA_LICENSE_TOKEN required", file=sys.stderr)
        sys.exit(1)
    try:
        payload = verify_token(token, secret)
        print(json.dumps({
            "valid":      True,
            "licensee":   payload["licensee"],
            "features":   payload["features"],
            "expires_at": payload["expires_at"],
            "build_count": payload.get("build_count", 0),
            "build_limit": payload["build_limit"],
        }, indent=2))
    except ValueError as e:
        print(json.dumps({"valid": False, "error": str(e)}, indent=2))
        sys.exit(1)


def cmd_record_build(args) -> None:
    token = args.token or os.environ.get("KAGURA_LICENSE_TOKEN", "")
    if not token:
        print("ERROR: --token or KAGURA_LICENSE_TOKEN required", file=sys.stderr)
        sys.exit(1)
    if args.validate:
        secret = _get_secret()
        verify_token(token, secret)
    payload = decode_token(token)
    conn = open_db(args.db)
    new_count = db_increment_build(conn, payload["token_id"])
    conn.close()
    if new_count == -1:
        print(json.dumps({"ok": False,
                          "error": "Build limit reached"}), indent=2)
        sys.exit(1)
    print(json.dumps({"ok": True, "build_count": new_count}, indent=2))


def cmd_list(args) -> None:
    conn = open_db(args.db)
    entries = db_list(conn)
    conn.close()
    print(json.dumps(entries, indent=2))


def cmd_revoke(args) -> None:
    conn = open_db(args.db)
    db_revoke(conn, args.token_id)
    conn.close()
    print(json.dumps({"revoked": args.token_id}))


def main():
    parser = argparse.ArgumentParser(description="kagura license manager")
    parser.add_argument("--db", default=DEFAULT_DB,
                        help="License database path")

    sub = parser.add_subparsers(dest="command")

    # generate
    gen = sub.add_parser("generate", help="Generate a new license token")
    gen.add_argument("--licensee", required=True)
    gen.add_argument("--features", default="fla,bcf,str,sub,co",
                     help="Comma-separated kagura pass names")
    gen.add_argument("--days", type=int, default=365,
                     help="Token validity in days (0 = never expire)")
    gen.add_argument("--build-limit", type=int, default=0,
                     help="Max builds (0 = unlimited)")

    # validate
    val = sub.add_parser("validate", help="Validate a token")
    val.add_argument("--token", default=None)

    # record-build
    rb = sub.add_parser("record-build",
                        help="Increment build counter in DB")
    rb.add_argument("--token", default=None)
    rb.add_argument("--validate", action="store_true",
                    help="Also verify HMAC before recording")

    # list
    sub.add_parser("list", help="List all licenses in DB")

    # revoke
    rev = sub.add_parser("revoke", help="Revoke a license by token ID")
    rev.add_argument("--token-id", required=True)

    args = parser.parse_args()

    if args.command == "generate":
        cmd_generate(args)
    elif args.command == "validate":
        cmd_validate(args)
    elif args.command == "record-build":
        cmd_record_build(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "revoke":
        cmd_revoke(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
