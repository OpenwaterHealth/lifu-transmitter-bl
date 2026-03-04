#!/usr/bin/env python3
"""Generate ECDSA P-256 signing keys and export bootloader-compatible public key formats.

Outputs:
- Private key PEM (PKCS8)
- Public key PEM (SubjectPublicKeyInfo)
- Raw public key bytes (64-byte x||y, big-endian)
- Optional C initializer snippet for g_bl_pubkeys[]
"""

import argparse
import secrets
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError as exc:
    raise SystemExit(
        "Missing dependency 'cryptography'. Install with: python -m pip install cryptography"
    ) from exc


def _format_c_bytes(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 8):
        chunk = data[i : i + 8]
        parts = ", ".join(f"0x{b:02X}U" for b in chunk)
        lines.append(f"      {parts},")
    return "\n".join(lines)


def _build_c_entry(key_id: int, pub_xy: bytes) -> str:
    if len(pub_xy) != 64:
        raise ValueError("pub_xy must be exactly 64 bytes")

    return (
        "{\n"
        f"  {key_id}U,\n"
        "  {\n"
        f"{_format_c_bytes(pub_xy)}\n"
        "  },\n"
        "},\n"
    )


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate ECDSA P-256 keypair for test signing + bootloader public key table"
    )
    parser.add_argument("--private-out", default="keys/fw_signing_key.pem", help="Private key PEM output path")
    parser.add_argument("--public-out", default="keys/fw_signing_pub.pem", help="Public key PEM output path")
    parser.add_argument(
        "--pub-xy-out",
        default="keys/fw_signing_pub.xy.bin",
        help="Raw public key output path (64-byte x||y)",
    )
    parser.add_argument("--key-id", type=int, default=1, help="Key ID for generated C entry")
    parser.add_argument(
        "--c-out",
        default="",
        help="Optional output path for C entry snippet (if omitted, snippet is printed only)",
    )
    parser.add_argument(
        "--trust-key-out",
        default="keys/boot_trust_hmac_key.bin",
        help="Optional output path for 32-byte trust HMAC key (empty to skip)",
    )

    args = parser.parse_args()

    private_path = Path(args.private_out)
    public_path = Path(args.public_out)
    pub_xy_path = Path(args.pub_xy_out)
    trust_key_path = Path(args.trust_key_out) if args.trust_key_out else None

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    nums = public_key.public_numbers()
    pub_xy = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    _write(private_path, private_pem)
    _write(public_path, public_pem)
    _write(pub_xy_path, pub_xy)

    if trust_key_path is not None:
        trust_key = secrets.token_bytes(32)
        _write(trust_key_path, trust_key)

    c_entry = _build_c_entry(args.key_id, pub_xy)
    if args.c_out:
        c_out_path = Path(args.c_out)
        c_out_path.parent.mkdir(parents=True, exist_ok=True)
        c_out_path.write_text(c_entry, encoding="utf-8")

    print(f"Private key PEM: {private_path}")
    print(f"Public key PEM : {public_path}")
    print(f"Public key x||y: {pub_xy_path} ({len(pub_xy)} bytes)")
    if trust_key_path is not None:
        print(f"Trust HMAC key : {trust_key_path} (32 bytes)")
    print("")
    print("Paste this into g_bl_pubkeys[]:")
    print(c_entry)
    if args.c_out:
        print(f"C entry file    : {args.c_out}")


if __name__ == "__main__":
    main()
