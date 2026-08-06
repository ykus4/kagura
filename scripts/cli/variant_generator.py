#!/usr/bin/env python3
"""
variant_generator.py — Kagura per-customer / per-app variant generator.

4.2.8: Produces a unique kagura.json config + per-variant key material for
each customer or application build variant.  Variants differ in:

  - Encryption keys  (AES-128 key + IV per string-encryption pass)
  - FNV nonce seeds  (BBCheck discriminators, IBR nonces, CO MBA coefficients)
  - Pass selection   (optional per-customer pass overrides)
  - Symbol suffix    (unique obfuscated name prefix to hinder cross-app analysis)

Usage
-----
  # Generate variant config for a single customer
  python3 variant_generator.py generate \\
      --customer "Acme Corp" --app-id com.acme.app \\
      --profile BALANCED --output acme_kagura.json

  # Batch-generate for a customer manifest
  python3 variant_generator.py batch --manifest customers.json \\
      --outdir variants/

  # Show what keys are embedded in an existing variant config
  python3 variant_generator.py inspect --config acme_kagura.json

Output (acme_kagura.json):
  {
    "variant_id":    "a3f2c9d1",
    "customer":      "Acme Corp",
    "app_id":        "com.acme.app",
    "profile":       "BALANCED",
    "passes":        ["str", "bcf", "fla", ...],
    "keys": {
      "str_key":     "0xdeadbeef...",   // 16-byte AES key (hex)
      "str_iv":      "0x...",           // 16-byte AES IV  (hex)
      "nonce_seed":  "0x...",           // 8-byte seed for FNV-based nonces
      "sym_prefix":  "k_a3f2c9d1_"
    },
    "protect":  ["*"],
    "deny":     [],
    "created_at": 1715000000
  }

The generated JSON is suitable for direct use as kagura's --kagura-config=
input.  The keys section is parsed by the C++ ConfigLoaderPass and forwarded
to each pass that accepts per-build key material.

Customer manifest format (customers.json):
  [
    { "customer": "Acme Corp", "app_id": "com.acme.app", "profile": "STRONG" },
    { "customer": "Beta Inc",  "app_id": "net.beta.sdk",  "profile": "BALANCED" }
  ]
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from typing import Optional

# ---- Profiles (same names as attacker_cost_model.py) -----------------------

PROFILES = {
    "FAST":     ["str", "sv"],
    "BALANCED": ["str", "str-aes", "sv", "fla", "bcf", "bbs", "bbr"],
    "STRONG":   ["str", "str-aes", "wstr", "sv", "fla", "bcf", "bbs",
                 "bbr", "dci", "co", "ibr", "ci", "genc", "mvo", "lt"],
}


# ---- Key material generation -----------------------------------------------

def _hex(data: bytes) -> str:
    return "0x" + data.hex()


def generate_key_material(variant_id: str) -> dict:
    """Generate deterministic-looking but cryptographically random keys."""
    return {
        "str_key":    _hex(secrets.token_bytes(16)),
        "str_iv":     _hex(secrets.token_bytes(16)),
        "str_aes_key": _hex(secrets.token_bytes(16)),
        "str_aes_iv":  _hex(secrets.token_bytes(16)),
        "nonce_seed": _hex(secrets.token_bytes(8)),
        "sym_prefix": f"k_{variant_id}_",
    }


def derive_variant_id(customer: str, app_id: str) -> str:
    """8-char hex ID derived from customer + app_id + random salt."""
    salt = secrets.token_bytes(4)
    digest = hashlib.sha256(
        f"{customer}|{app_id}".encode() + salt
    ).hexdigest()
    return digest[:8]


# ---- Single variant generation ---------------------------------------------

def generate_variant(
    customer: str,
    app_id: str,
    profile: str,
    extra_passes: Optional[list] = None,
    protect: Optional[list] = None,
    deny: Optional[list] = None,
) -> dict:
    profile_upper = profile.upper()
    if profile_upper not in PROFILES:
        raise ValueError(f"Unknown profile: {profile}. "
                         f"Choose from {list(PROFILES)}")
    passes = list(PROFILES[profile_upper])
    if extra_passes:
        for p in extra_passes:
            if p not in passes:
                passes.append(p)

    variant_id = derive_variant_id(customer, app_id)
    keys = generate_key_material(variant_id)

    return {
        "variant_id":  variant_id,
        "customer":    customer,
        "app_id":      app_id,
        "profile":     profile_upper,
        "passes":      passes,
        "keys":        keys,
        "protect":     protect or ["*"],
        "deny":        deny or [],
        "created_at":  int(time.time()),
    }


# ---- Commands --------------------------------------------------------------

def cmd_generate(args) -> None:
    extra = ([p.strip() for p in args.extra_passes.split(",") if p.strip()]
             if args.extra_passes else None)
    protect = ([p.strip() for p in args.protect.split(",") if p.strip()]
               if args.protect else None)
    deny = ([p.strip() for p in args.deny.split(",") if p.strip()]
            if args.deny else None)

    variant = generate_variant(
        args.customer, args.app_id, args.profile,
        extra, protect, deny,
    )

    out = json.dumps(variant, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
        print(f"Variant config written to: {args.output}")
        print(f"  variant_id: {variant['variant_id']}")
        print(f"  profile:    {variant['profile']}")
        print(f"  passes:     {', '.join(variant['passes'])}")
    else:
        print(out)


def cmd_batch(args) -> None:
    with open(args.manifest) as f:
        customers = json.load(f)

    os.makedirs(args.outdir, exist_ok=True)
    results = []

    for entry in customers:
        customer = entry["customer"]
        app_id = entry["app_id"]
        profile = entry.get("profile", "BALANCED")
        extra = entry.get("extra_passes", None)
        protect = entry.get("protect", None)
        deny = entry.get("deny", None)

        variant = generate_variant(customer, app_id, profile,
                                   extra, protect, deny)

        # Sanitize filename: replace spaces/slashes
        safe_name = app_id.replace("/", "_").replace(" ", "_")
        out_path = os.path.join(args.outdir, f"{safe_name}.json")
        with open(out_path, "w") as f:
            json.dump(variant, f, indent=2)

        results.append({
            "customer":   customer,
            "app_id":     app_id,
            "variant_id": variant["variant_id"],
            "config":     out_path,
        })
        print(f"  [{variant['variant_id']}] {customer} / {app_id} → {out_path}")

    summary_path = os.path.join(args.outdir, "variants_summary.json")
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSummary written to: {summary_path}")


def cmd_inspect(args) -> None:
    with open(args.config) as f:
        variant = json.load(f)

    print(f"variant_id : {variant.get('variant_id')}")
    print(f"customer   : {variant.get('customer')}")
    print(f"app_id     : {variant.get('app_id')}")
    print(f"profile    : {variant.get('profile')}")
    print(f"passes     : {', '.join(variant.get('passes', []))}")
    print(f"created_at : {variant.get('created_at')}")
    print()
    keys = variant.get("keys", {})
    for k, v in keys.items():
        # Mask the middle of key values
        if len(v) > 10:
            masked = v[:6] + "..." + v[-4:]
        else:
            masked = v
        print(f"  {k:<16} {masked}")


# ---- Main ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="kagura per-customer variant generator (4.2.8)"
    )
    sub = parser.add_subparsers(dest="command")

    # generate
    gen = sub.add_parser("generate", help="Generate a single variant config")
    gen.add_argument("--customer", required=True, help="Customer name")
    gen.add_argument("--app-id", required=True,
                     help="Bundle / package identifier")
    gen.add_argument("--profile", default="BALANCED",
                     choices=list(PROFILES), help="Protection profile")
    gen.add_argument("--extra-passes", default=None,
                     help="Additional passes beyond profile (csv)")
    gen.add_argument("--protect", default=None,
                     help="Protect glob patterns (csv, default *)")
    gen.add_argument("--deny", default=None,
                     help="Deny glob patterns (csv)")
    gen.add_argument("--output", "-o", default=None,
                     help="Output JSON path (default: stdout)")

    # batch
    batch = sub.add_parser("batch",
                           help="Batch-generate from a customer manifest JSON")
    batch.add_argument("--manifest", required=True,
                       help="Path to customers.json")
    batch.add_argument("--outdir", required=True,
                       help="Output directory for variant configs")

    # inspect
    ins = sub.add_parser("inspect",
                         help="Inspect an existing variant config")
    ins.add_argument("--config", required=True)

    args = parser.parse_args()

    if args.command == "generate":
        cmd_generate(args)
    elif args.command == "batch":
        cmd_batch(args)
    elif args.command == "inspect":
        cmd_inspect(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
