#!/usr/bin/env python3
# cryptodude_encrypt.py
#
# Create SJCL-compatible encrypted JSON from an input HTML file.
# Compatible with sjcl.decrypt(password, dataJsonString) in your viewer HTML.

import argparse
import base64
import json
import os
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


@dataclass
class SjclParams:
    v: int = 1
    iter: int = 600_000          # PBKDF2 iterations
    ks: int = 128                # key size in bits
    ts: int = 128                # tag size in bits (64/96/128)
    mode: str = "ccm"
    cipher: str = "aes"
    adata: str = ""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _derive_key(password: str, salt: bytes, iterations: int, key_bits: int) -> bytes:
    if key_bits % 8 != 0:
        raise ValueError("Key size must be a multiple of 8 bits.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_bits // 8,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _sjcl_ccm_L_from_msg_len(msg_len_bytes: int) -> int:
    """
    SJCL's CCM uses 'f' internally (called L in some descriptions).
    SJCL computes f like:
        f = 2
        while f < 4 and msg_len >>> (8*f): f++
    For most HTML files (< 64 KiB), f will be 2.
    """
    f = 2
    while f < 4 and (msg_len_bytes >> (8 * f)) != 0:
        f += 1
    return f  # 2..4


def encrypt_html_to_sjcl_json(
    html_bytes: bytes,
    password: str,
    params: SjclParams,
    salt_bytes: int = 8,   # SJCL default: randomWords(2) => 8 bytes
    iv_bytes: int = 16,    # SJCL default: randomWords(4) => 16 bytes
) -> dict:
    if params.mode != "ccm" or params.cipher != "aes":
        raise ValueError("This script currently supports only AES-CCM (mode='ccm', cipher='aes').")
    if params.ks not in (128, 192, 256):
        raise ValueError("ks must be 128, 192, or 256.")
    if params.ts not in (64, 96, 128):
        raise ValueError("ts must be 64, 96, or 128.")
    if params.iter < 10_000:
        raise ValueError("iter is very low; choose >= 10000 (recommend much higher).")

    salt = os.urandom(salt_bytes)
    iv_full = os.urandom(iv_bytes)

    # Match SJCL behavior: it stores full 16-byte IV, but CCM internally uses a truncated nonce:
    # nonce_len = 15 - f  (where f depends on message length)
    f = _sjcl_ccm_L_from_msg_len(len(html_bytes))
    nonce_len = 15 - f  # typically 13
    if nonce_len < 7 or nonce_len > 13:
        raise ValueError(f"Unexpected nonce length computed: {nonce_len}")
    nonce = iv_full[:nonce_len]

    key = _derive_key(password, salt, params.iter, params.ks)

    aesccm = AESCCM(key, tag_length=params.ts // 8)
    adata_bytes = params.adata.encode("utf-8") if params.adata else b""
    ct = aesccm.encrypt(nonce, html_bytes, adata_bytes)  # ciphertext || tag

    # Build SJCL JSON structure (ct is base64; iv & salt are base64)
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


def main():
    ap = argparse.ArgumentParser(description="Encrypt an HTML file into SJCL-compatible JSON (AES-CCM + PBKDF2-SHA256).")
    ap.add_argument("input_html", help="Path to input HTML file (plaintext).")
    ap.add_argument("-o", "--output", help="Output file path (JSON). If omitted, prints to stdout.")
    ap.add_argument("-p", "--password", help="Password. If omitted, read from CRYPTODUDE_PASSWORD env var.")
    ap.add_argument("--iter", type=int, default=600_000, help="PBKDF2 iterations (default: 600000).")
    ap.add_argument("--ks", type=int, default=128, choices=[128, 192, 256], help="Key size bits (default: 128).")
    ap.add_argument("--ts", type=int, default=128, choices=[64, 96, 128], help="Tag size bits (default: 128).")
    args = ap.parse_args()

    password = args.password or os.environ.get("CRYPTODUDE_PASSWORD")
    if not password:
        raise SystemExit("No password provided. Use -p/--password or set CRYPTODUDE_PASSWORD.")

    with open(args.input_html, "rb") as f:
        html = f.read()

    params = SjclParams(iter=args.iter, ks=args.ks, ts=args.ts)
    obj = encrypt_html_to_sjcl_json(html, password, params=params)

    out = json.dumps(obj, separators=(",", ":"))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Wrote {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
