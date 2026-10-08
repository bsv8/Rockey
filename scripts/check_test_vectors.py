#!/usr/bin/env python3
"""校验固件内嵌的自检向量是否与权威来源一致。

避免"把错的期望值烧进设备、开机自检失败、却以为是硬件问题"。

权威来源：
  - X25519：RFC 7748 §5.2 / §6.1
  - AES-256-GCM：NIST SP 800-38D / GCM 规范测试用例
  - RIPEMD-160：ISO/IEC 10118-3 官方向量
  - 本地秘密 v3：keymaster.cc active-key-hkdf-v1（WebCrypto AES-GCM 等价）

用法：python3 scripts/check_test_vectors.py
"""
import binascii
import hashlib
import hmac
import re
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = []


def check(name, got, want):
    if got != want:
        fails.append(f"{name}: got {got} want {want}")
        print(f"  FAIL {name}\n       got  {got}\n       want {want}")
    else:
        print(f"  ok   {name}")


def arrays_from(path):
    src = open(os.path.join(ROOT, path), encoding="utf-8").read()
    out = {}
    for m in re.finditer(r"(\w+)\[(\d+)\]\s*=\s*\{(.*?)\};", src, re.S):
        name = m.group(1)
        body = m.group(3)
        vals = re.findall(r"0x([0-9a-fA-F]{2})", body)
        if vals:
            out.setdefault(name, []).append("".join(vals))
    return out


# ── X25519 (RFC 7748) ─────────────────────────────────────────────────────
print("X25519 / RFC 7748")
a = arrays_from("src/crypto/x25519.cpp")
check("rfc7748 k1", a["k1"][0], "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
check("rfc7748 u1", a["u1"][0], "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
check("rfc7748 o1", a["o1"][0], "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
check("rfc7748 k2", a["k2"][0], "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
check("rfc7748 u2", a["u2"][0], "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
check("rfc7748 o2", a["o2"][0], "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
check("rfc7748 iter1000", a["kIter1000"][0],
      "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")

# ── AES-256-GCM (NIST) ───────────────────────────────────────────────────
print("AES-256-GCM / NIST")
a = arrays_from("src/crypto/aead.cpp")
check("tc1 tag", a["kExpect"][0], "58e2fccefa7e3061367f1d57a4e7455a")
check("tc2 ct", a["kExpectCt"][0], "0388dace60b6a392f328c2b971b2fe78")
check("tc2 tag", a["kExpectTag"][0], "ab6e47d42cec13bdf53a67b21257bddf")
check("tc4 ct", a["kExpectCt"][1], "cea7403d4d606b6e074ec5d3baf39d18")
check("tc4 tag", a["kExpectTag"][1], "d0d1c8a799996bf0265b98b5d48ab919")

# ── RIPEMD-160 ───────────────────────────────────────────────────────────
print("RIPEMD-160 / ISO 10118-3")
RIPEMD = {
    "": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
    "a": "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
    "abc": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    "message digest": "5d0689ef49d2fae572b881b123a85ffa21595f36",
    "abcdefghijklmnopqrstuvwxyz": "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
}
src = open(os.path.join(ROOT, "src/crypto/ripemd160.cpp"), encoding="utf-8").read()
embedded = set(re.findall(r'"([0-9a-f]{40})"', src))
for msg, want in RIPEMD.items():
    try:
        got = hashlib.new("ripemd160", msg.encode()).hexdigest()
    except Exception as exc:  # pragma: no cover
        fails.append(f"host has no ripemd160: {exc}")
        print("  skip host ripemd160 unavailable")
        break
    check(f"authoritative {msg[:16]!r}", got, want)
    check(f"embedded {msg[:16]!r}", want in embedded, True)

# ── 本地秘密 v3 ──────────────────────────────────────────────────────────
print("local-secret v3 / keymaster active-key-hkdf-v1")


def hkdf_sha256(ikm, salt, info, n=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:n]


try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    priv = bytes(31) + b"\x01"
    pubhex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    scope = b"storage.bucket-password"
    salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    nonce = bytes.fromhex("101112131415161718191a1b")
    key = hkdf_sha256(priv, b"keymaster.vault.local-secret.v3", pubhex.encode() + b"\x00" + scope)
    check("derived key", binascii.hexlify(key).decode(),
          "8b9534f16d1eec1714c3c5642652d3eff0a9f7b72e5da4e9973d666e8b259112")
    aad = b"keymaster:local-secret:v3|" + scope + b"\x00" + salt
    ct = AESGCM(key).encrypt(nonce, b"provider-secret", aad)
    check("ciphertext||tag", binascii.hexlify(ct).decode(),
          "ea07bec9b7f461d91d00f279b9ade38303baa3f1a28fd7373775c784e78f41")
except ImportError:
    print("  skip host cryptography unavailable")

la = arrays_from("src/ops/local_secret.cpp")
check("embedded derived key", la["kExpectKey"][0],
      "8b9534f16d1eec1714c3c5642652d3eff0a9f7b72e5da4e9973d666e8b259112")
check("embedded ciphertext", la["kExpectCt"][0],
      "ea07bec9b7f461d91d00f279b9ade38303baa3f1a28fd7373775c784e78f41")
src = open(os.path.join(ROOT, "src/ops/local_secret.cpp"), encoding="utf-8").read()
check("embedded pubkey hex",
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" in src, True)

print()
if fails:
    print(f"FAILED: {len(fails)} problem(s)")
    sys.exit(1)
print("all embedded self-test vectors match authoritative sources")