"""质量凭据的签名与验证（Ed25519，非分离式 canonical JSON 签名）。

签名私钥在首次使用时生成并保存到 ``meta`` 表；公钥通过 API 对外公布，
任何持有凭据文件（正文 + 签名）的一方均可离线验签，确认裁决在冻结时刻
由本平台签发，且正文（含规则版本、失败数、豁免清单）未被篡改。
"""
from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

META_PRIV_KEY = "credential_signing_key_pem"
META_PUB_KEY = "credential_verifying_key_pem"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def canonical(body: dict) -> bytes:
    return json.dumps(body, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def get_or_create_keypair(store) -> tuple[str, str]:
    """返回 (private_pem_b64, public_pem_b64)；惰性生成并持久化。"""
    with store.tx(write=True) as conn:
        row = store.qone(conn, "SELECT value FROM meta WHERE key=?", (META_PRIV_KEY,))
        if row is not None:
            priv_pem = row["value"]
            pub = store.qone(conn, "SELECT value FROM meta WHERE key=?", (META_PUB_KEY,))["value"]
            return priv_pem, pub
        key = Ed25519PrivateKey.generate()
        priv_pem = _b64(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        pub_pem = _b64(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
        conn.execute("INSERT INTO meta(key,value) VALUES(?,?)", (META_PRIV_KEY, priv_pem))
        conn.execute("INSERT INTO meta(key,value) VALUES(?,?)", (META_PUB_KEY, pub_pem))
        return priv_pem, pub_pem


def get_public_key_pem(store) -> str:
    with store.tx() as conn:
        row = store.qone(conn, "SELECT value FROM meta WHERE key=?", (META_PUB_KEY,))
    if row is None:
        # 惰性生成，保证随时可验证
        return get_or_create_keypair(store)[1]
    return row["value"]


def sign_body(store, body: dict) -> str:
    priv_pem, _ = get_or_create_keypair(store)
    return sign_with_pem(priv_pem, body)


def sign_with_pem(priv_pem_b64: str, body: dict) -> str:
    key: Ed25519PrivateKey = serialization.load_pem_private_key(
        base64.b64decode(priv_pem_b64), password=None)
    return _b64(key.sign(canonical(body)))


def verify_body(public_pem_b64: str, body: dict, signature_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(base64.b64decode(public_pem_b64))
        pub.verify(base64.b64decode(signature_b64), canonical(body))
        return True
    except (InvalidSignature, ValueError):
        return False
