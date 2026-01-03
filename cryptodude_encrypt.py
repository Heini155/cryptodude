#!/usr/bin/env python3
"""
Cryptodude Encrypt v1.1
======================

Encrypts an input HTML file into an SJCL-compatible JSON blob
(AES-CCM + PBKDF2-HMAC-SHA256) for use with your template.html viewer.

Security improvements vs v1.0:
- Avoid passing passwords via CLI args by default (supports getpass / stdin / env).
- Guardrails + warnings for too-low PBKDF2 iterations and tag length.
- Friendlier error messages with actionable hints.
- Clear "only AES-CCM supported" structure, easy to extend later.

Requires:
  pip install cryptography
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from dataclasses import dataclass
from typing import Optional, TextIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import getpass
except ImportError:  # extremely rare
    getpass = None


@dataclass(frozen=True)
class SjclParams:
    v: int = 1
    iter: int = 600_000          # PBKDF2 iterations (default recommended)
    ks: int = 128                # key size in bits
    ts: int = 128                # tag size in bits (64/96/128)
    mode: str = "ccm"
    cipher: str = "aes"
    adata: str = ""


class UserError(Exception):
    """Error with a user-facing message."""


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def warn(msg: str) -> None:
    eprint(f"WARNING: {msg}")


def _b64(b: bytes) -> str:
    # base64 is ASCII-safe by definition; decode('ascii') ensures we fail loudly if something is wrong
    return base64.b64encode(b).decode("ascii")


def _derive_key(password: str, salt: bytes, iterations: int, key_bits: int) -> bytes:
    if key_bits % 8 != 0:
        raise UserError("Key size (ks) must be a multiple of 8 bits.")
    if iterations <= 0:
        raise UserError("PBKDF2 iterations (iter) must be a positive integer.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_bits // 8,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _sjcl_ccm_L_from_msg_len(msg_len_bytes: int) -> int:
    """
    SJCL's CCM chooses L ("f" in SJCL code) based on message length:
      f = 2
      while f < 4 and msg_len >>> (8*f): f++

    This affects nonce length: nonce_len = 15 - f (typically 13 for < 64 KiB).
    """
    f = 2
    while f < 4 and (msg_len_bytes >> (8 * f)) != 0:
        f += 1
    return f  # 2..4


def encrypt_html_to_sjcl_json(
    html_bytes: bytes,
    password: str,
    params: SjclParams,
    salt_bytes: int = 8,   # SJCL typical default: 8 bytes
    iv_bytes: int = 16,    # SJCL typical default: 16 bytes
) -> dict:
    # Guard: this tool currently matches your SJCL viewer expectations
    if params.mode != "ccm":
        raise UserError("Only mode='ccm' is supported in v1.1 (SJCL-compatible).")
    if params.cipher != "aes":
        raise UserError("Only cipher='aes' is supported in v1.1 (SJCL-compatible).")
    if params.ks not in (128, 192, 256):
        raise UserError("ks must be 128, 192, or 256.")
    if params.ts not in (64, 96, 128):
        raise UserError("ts must be 64, 96, or 128.")
    if salt_bytes < 8:
        raise UserError("salt_bytes is too small; use at least 8 bytes (SJCL default is 8).")
    if iv_bytes < 12:
        raise UserError("iv_bytes is too small; use 16 bytes (SJCL default is 16).")

    salt = os.urandom(salt_bytes)
    iv_full = os.urandom(iv_bytes)

    # Match SJCL behavior: store full IV, but CCM uses a nonce of length (15 - f)
    f = _sjcl_ccm_L_from_msg_len(len(html_bytes))
    nonce_len = 15 - f  # typically 13
    if not (7 <= nonce_len <= 13):
        raise UserError(f"Computed CCM nonce length is invalid: {nonce_len} (must be 7..13).")
    nonce = iv_full[:nonce_len]

    key = _derive_key(password, salt, params.iter, params.ks)
    aesccm = AESCCM(key, tag_length=params.ts // 8)

    adata_bytes = params.adata.encode("utf-8") if params.adata else b""
    ct = aesccm.encrypt(nonce, html_bytes, adata_bytes)  # ciphertext || tag

    return {
        "iv": _b64(iv_full),
        "v": params.v,
        "iter": params.iter,
        "ks": params.ks,
        "ts": params.ts,
        "mode": params.mode,
        "adata": params.adata,
        "cipher": params.cipher,
        "salt": _b64(salt),
        "ct": _b64(ct),
    }


def _read_password_from_stdin(stream: TextIO) -> str:
    # Reads entire stdin (useful for pipes). Strips trailing newline.
    pw = stream.read()
    pw = pw.rstrip("\r\n")
    return pw


def _get_password(args: argparse.Namespace) -> str:
    """
    Password precedence:
      1) --password-stdin
      2) CRYPTODUDE_PASSWORD env var
      3) interactive prompt (getpass)
      4) (optional/legacy) --password (discouraged; warns)
    """
    if args.password_stdin:
        pw = _read_password_from_stdin(sys.stdin)
        if not pw:
            raise UserError("--password-stdin was set, but stdin was empty.")
        return pw

    if args.password_env:
        pw = os.environ.get(args.password_env)
        if pw:
            return pw
        raise UserError(f"Environment variable '{args.password_env}' is not set or empty.")

    if args.password is not None:
        warn("Using --password exposes secrets in shell history and possibly process listings. "
             "Prefer --password-stdin or an env var (default: CRYPTODUDE_PASSWORD).")
        if args.password == "":
            raise UserError("--password was provided but empty.")
        return args.password

    # Default: env var CRYPTODUDE_PASSWORD if set, else prompt
    pw = os.environ.get("CRYPTODUDE_PASSWORD")
    if pw:
        return pw

    if getpass is None:
        raise UserError("Interactive password prompt unavailable. Use --password-stdin or set CRYPTODUDE_PASSWORD.")
    pw = getpass.getpass("Password: ")
    if not pw:
        raise UserError("Empty password is not allowed.")
    return pw


def _guardrails(iterations: int, ts: int, allow_weak: bool) -> None:
    # You can tune these thresholds as you like:
    HARD_MIN_ITER = 50_000
    WARN_MIN_ITER = 200_000

    if iterations < HARD_MIN_ITER:
        msg = (f"PBKDF2 iterations (iter={iterations}) is dangerously low. "
               f"Use >= {WARN_MIN_ITER} (recommended default is 600000).")
        if allow_weak:
            warn(msg + " Proceeding due to --allow-weak.")
        else:
            raise UserError(msg + " If you really want this, pass --allow-weak.")
    elif iterations < WARN_MIN_ITER:
        warn(f"PBKDF2 iterations (iter={iterations}) is lower than recommended. "
             f"Consider >= {WARN_MIN_ITER} (default: 600000).")

    if ts < 128:
        warn(f"Auth tag length (ts={ts}) is lower than recommended (128). "
             "It still works, but 128 is standard for AEAD.")


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Encrypt an HTML file into SJCL-compatible JSON (AES-CCM + PBKDF2-SHA256).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("input_html", help="Path to input HTML file (plaintext).")
    ap.add_argument("-o", "--output", help="Output file path (JSON). If omitted, prints to stdout.")

    pw = ap.add_argument_group("password input (recommended: stdin/env)")
    pw.add_argument("--password-stdin", action="store_true",
                    help="Read password from stdin (recommended for automation).")
    pw.add_argument("--password-env", default=None,
                    help="Read password from the given environment variable name.")
    pw.add_argument("-p", "--password", default=None,
                    help="Password as CLI argument (DISCOURAGED).")

    crypto = ap.add_argument_group("crypto parameters")
    crypto.add_argument("--iter", type=int, default=600_000,
                        help="PBKDF2 iterations.")
    crypto.add_argument("--ks", type=int, default=128, choices=[128, 192, 256],
                        help="Key size bits.")
    crypto.add_argument("--ts", type=int, default=128, choices=[64, 96, 128],
                        help="Auth tag size bits.")
    crypto.add_argument("--adata", type=str, default="",
                        help="Additional authenticated data (AAD). Keep empty unless you know why you need it.")

    compat = ap.add_argument_group("SJCL compatibility")
    compat.add_argument("--salt-bytes", type=int, default=8,
                        help="Salt length in bytes (SJCL commonly uses 8).")
    compat.add_argument("--iv-bytes", type=int, default=16,
                        help="IV length in bytes (SJCL commonly uses 16).")

    ap.add_argument("--allow-weak", action="store_true",
                    help="Allow weak parameters (e.g. very low iter). Not recommended.")
    return ap


def main() -> int:
    ap = build_arg_parser()
    args = ap.parse_args()

    try:
        password = _get_password(args)
        _guardrails(args.iter, args.ts, args.allow_weak)

        # Read input
        try:
            with open(args.input_html, "rb") as f:
                html = f.read()
        except FileNotFoundError:
            raise UserError(f"Input file not found: {args.input_html}")
        except PermissionError:
            raise UserError(f"No permission to read input file: {args.input_html}")

        params = SjclParams(iter=args.iter, ks=args.ks, ts=args.ts, adata=args.adata)

        obj = encrypt_html_to_sjcl_json(
            html_bytes=html,
            password=password,
            params=params,
            salt_bytes=args.salt_bytes,
            iv_bytes=args.iv_bytes,
        )

        out = json.dumps(obj, separators=(",", ":"))

        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(out)
            except PermissionError:
                raise UserError(f"No permission to write output file: {args.output}")
            print(f"Wrote {args.output}")
        else:
            print(out)

        return 0

    except UserError as ue:
        eprint(f"ERROR: {ue}")
        eprint("")
        eprint("Hints:")
        eprint("  - Prefer:  echo -n 'your password' | python cryptodude_encrypt.py geheim.html --password-stdin -o data.json")
        eprint("  - Or:      export CRYPTODUDE_PASSWORD='...' ; python cryptodude_encrypt.py geheim.html -o data.json")
        eprint("  - Install: pip install cryptography")
        return 2

    except KeyboardInterrupt:
        eprint("\nAborted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
