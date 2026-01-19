"""
纯 Python 实现的 RSA（含 OAEP 填充）示例程序。

支持：
- 生成 RSA 密钥对（2048/3072/4096 bits）
- 使用 RSAES-OAEP（SHA-256）加密/解密文本
- 将密钥保存为 JSON（n,e / n,d）

说明：
- 这是教学/练习级实现；生产环境建议使用成熟库（如 cryptography）。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import secrets
from dataclasses import dataclass
from typing import Tuple


# -----------------------------
# 数学工具：素性测试 / 生成大素数
# -----------------------------


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin 素性测试（概率性）。"""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # n-1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_odd_int(bits: int) -> int:
    if bits < 2:
        raise ValueError("bits must be >= 2")
    x = secrets.randbits(bits)
    x |= (1 << (bits - 1))  # ensure top bit
    x |= 1  # odd
    return x


def generate_prime(bits: int) -> int:
    """生成指定位数的大素数。"""
    while True:
        candidate = _random_odd_int(bits)
        if _is_probable_prime(candidate):
            return candidate


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """扩展欧几里得：返回 (g,x,y) 使得 ax+by=g=gcd(a,b)"""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


# -----------------------------
# RSA Key
# -----------------------------


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    @property
    def k(self) -> int:
        """模数长度（字节）"""
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    d: int
    e: int

    @property
    def k(self) -> int:
        return (self.n.bit_length() + 7) // 8


def generate_keypair(bits: int = 2048, e: int = 65537) -> Tuple[RSAPublicKey, RSAPrivateKey]:
    if bits < 1024:
        raise ValueError("bits too small; use >= 1024 (建议 2048+)")
    if e % 2 == 0 or e < 3:
        raise ValueError("e must be an odd integer >= 3")

    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(bits - half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            d = modinv(e, phi)
            return RSAPublicKey(n=n, e=e), RSAPrivateKey(n=n, d=d, e=e)


# -----------------------------
# OAEP (SHA-256) 实现
# -----------------------------


def _i2osp(x: int, x_len: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    return x.to_bytes(x_len, byteorder="big")


def _os2ip(x: bytes) -> int:
    return int.from_bytes(x, byteorder="big")


def mgf1(seed: bytes, mask_len: int, hash_name: str = "sha256") -> bytes:
    h = hashlib.new(hash_name)
    h_len = h.digest_size
    if mask_len < 0:
        raise ValueError("mask_len must be >= 0")
    t = b""
    for counter in range(0, math.ceil(mask_len / h_len)):
        c = _i2osp(counter, 4)
        t += hashlib.new(hash_name, seed + c).digest()
    return t[:mask_len]


def oaep_encode(message: bytes, k: int, label: bytes = b"", hash_name: str = "sha256") -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if len(message) > k - 2 * h_len - 2:
        raise ValueError("message too long for RSA OAEP")
    l_hash = hashlib.new(hash_name, label).digest()
    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message
    seed = secrets.token_bytes(h_len)
    db_mask = mgf1(seed, k - h_len - 1, hash_name)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = mgf1(masked_db, h_len, hash_name)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded: bytes, k: int, label: bytes = b"", hash_name: str = "sha256") -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if len(encoded) != k:
        raise ValueError("decryption error (invalid length)")
    if k < 2 * h_len + 2:
        raise ValueError("decryption error (k too small)")
    if encoded[0] != 0:
        raise ValueError("decryption error (leading byte)")
    masked_seed = encoded[1 : 1 + h_len]
    masked_db = encoded[1 + h_len :]
    seed_mask = mgf1(masked_db, h_len, hash_name)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, k - h_len - 1, hash_name)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    l_hash = hashlib.new(hash_name, label).digest()
    l_hash_prime = db[:h_len]
    if l_hash_prime != l_hash:
        raise ValueError("decryption error (label hash mismatch)")

    # DB = lHash || PS || 0x01 || M
    rest = db[h_len:]
    # 找到 0x01 分隔符
    idx = rest.find(b"\x01")
    if idx == -1:
        raise ValueError("decryption error (separator not found)")
    # 0x01 之前必须全 0x00
    if any(b != 0 for b in rest[:idx]):
        raise ValueError("decryption error (bad padding)")
    return rest[idx + 1 :]


# -----------------------------
# RSA-OAEP 加解密
# -----------------------------


def rsa_encrypt_oaep(pub: RSAPublicKey, plaintext: bytes, label: bytes = b"", hash_name: str = "sha256") -> bytes:
    k = pub.k
    em = oaep_encode(plaintext, k=k, label=label, hash_name=hash_name)
    m = _os2ip(em)
    c = pow(m, pub.e, pub.n)
    return _i2osp(c, k)


def rsa_decrypt_oaep(priv: RSAPrivateKey, ciphertext: bytes, label: bytes = b"", hash_name: str = "sha256") -> bytes:
    k = priv.k
    if len(ciphertext) != k:
        raise ValueError("ciphertext length mismatch")
    c = _os2ip(ciphertext)
    m = pow(c, priv.d, priv.n)
    em = _i2osp(m, k)
    return oaep_decode(em, k=k, label=label, hash_name=hash_name)


# -----------------------------
# Key 文件读写（JSON）
# -----------------------------


def save_public_key(path: str, pub: RSAPublicKey) -> None:
    data = {"kty": "RSA", "n": str(pub.n), "e": str(pub.e)}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def save_private_key(path: str, priv: RSAPrivateKey) -> None:
    data = {"kty": "RSA", "n": str(priv.n), "e": str(priv.e), "d": str(priv.d)}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_public_key(path: str) -> RSAPublicKey:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return RSAPublicKey(n=int(data["n"]), e=int(data["e"]))


def load_private_key(path: str) -> RSAPrivateKey:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return RSAPrivateKey(n=int(data["n"]), e=int(data["e"]), d=int(data["d"]))


# -----------------------------
# CLI
# -----------------------------


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def main() -> None:
    parser = argparse.ArgumentParser(description="RSA (OAEP-SHA256) demo")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("gen", help="生成 RSA 密钥对")
    p_gen.add_argument("--bits", type=int, default=2048, help="密钥位数（默认 2048）")
    p_gen.add_argument("--pub", default="rsa_pub.json", help="公钥输出文件")
    p_gen.add_argument("--priv", default="rsa_priv.json", help="私钥输出文件")

    p_enc = sub.add_parser("enc", help="用公钥加密文本（输出 base64）")
    p_enc.add_argument("--pub", default="rsa_pub.json", help="公钥文件")
    p_enc.add_argument("--text", required=True, help="要加密的文本（UTF-8）")

    p_dec = sub.add_parser("dec", help="用私钥解密 base64 密文（输出明文）")
    p_dec.add_argument("--priv", default="rsa_priv.json", help="私钥文件")
    p_dec.add_argument("--b64", required=True, help="base64 密文")

    args = parser.parse_args()

    if args.cmd == "gen":
        pub, priv = generate_keypair(bits=args.bits)
        save_public_key(args.pub, pub)
        save_private_key(args.priv, priv)
        print(f"OK: generated {args.bits}-bit keypair")
        print(f"public:  {args.pub}")
        print(f"private: {args.priv}")
        return

    if args.cmd == "enc":
        pub = load_public_key(args.pub)
        ct = rsa_encrypt_oaep(pub, args.text.encode("utf-8"))
        print(_b64e(ct))
        return

    if args.cmd == "dec":
        priv = load_private_key(args.priv)
        pt = rsa_decrypt_oaep(priv, _b64d(args.b64))
        print(pt.decode("utf-8"))
        return


if __name__ == "__main__":
    main()
