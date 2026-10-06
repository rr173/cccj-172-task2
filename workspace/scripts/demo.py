"""端到端演练脚本：使用文件型 SQLite 走完整业务流并离线验签凭据。

    python3 scripts/demo.py
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app.api import create_app
from app.security import canonical
from app.storage import Store
from cryptography.hazmat.primitives import serialization


def pp(title: str, payload) -> None:
    print(f"\n=== {title} ===")
    print(json.dumps(payload, ensure_ascii=False, indent=2)[:1600])


def main() -> None:
    db = os.path.join(tempfile.mkdtemp(prefix="dq-demo-"), "demo.db")
    client = TestClient(create_app(Store(db)))

    # 1) 建产品（固定字段）
    pid = client.post("/products", json={
        "name": "交易快照",
        "tables": [
            {"name": "orders", "pk_column": "id", "columns": [
                {"name": "id", "type": "integer", "nullable": False},
                {"name": "customer_id", "type": "integer", "nullable": True},
                {"name": "amount", "type": "number", "nullable": True}]},
            {"name": "customers", "pk_column": "id", "columns": [
                {"name": "id", "type": "integer", "nullable": False},
                {"name": "tier", "type": "string", "nullable": True}]},
        ],
    }).json()["product_id"]

    # 2) 建规则
    rng = client.post("/rules", json={
        "product_id": pid, "name": "金额 0..1000", "kind": "value_range",
        "config": {"table": "orders", "column": "amount", "min": 0, "max": 1000},
    }).json()["rule_id"]
    client.post("/rules", json={
        "product_id": pid, "name": "客户外键", "kind": "cross_table",
        "config": {"left_table": "orders", "left_columns": ["customer_id"],
                   "right_table": "customers", "right_columns": ["id"]}})

    # 3) 装载含脏数据的快照并发布
    client.post(f"/products/{pid}/repair", json={"actor": "ingest", "upserts": {
        "orders": [
            {"id": 1, "customer_id": 10, "amount": 100},
            {"id": 2, "customer_id": 10, "amount": 9000},
            {"id": 3, "customer_id": 77, "amount": 50},
        ],
        "customers": [{"id": 10, "tier": "gold"}],
    }})
    rev1 = client.post(f"/products/{pid}/publish", json={"actor": "ingest"}).json()
    pp("发布 v1 / revision 1", {k: rev1[k] for k in
        ("data_version", "revision", "status", "failure_count", "verdict", "run_id")})

    # 4) 规则升级后回放历史快照 => revision 2（rev1 不变）
    client.post(f"/rules/{rng}/versions", json={
        "product_id": pid, "name": "金额 0..1000", "kind": "value_range",
        "config": {"table": "orders", "column": "amount", "min": 0, "max": 500}})
    rev2 = client.post(f"/products/{pid}/replay", json={"actor": "dq-team"}).json()
    pp("规则升级回放 => revision 2", {k: rev2[k] for k in
        ("revision", "trigger", "failure_count", "ruleset_fingerprint")})

    # 5) 工作台：对 rev2 的一条失败精确豁免
    run_id = rev2["run_id"]
    page = client.get(f"/runs/{run_id}/failures").json()["items"]
    target = next(f for f in page if f["row_pk"] == "2")
    ex = client.post("/exemptions", json={
        "run_id": run_id, "ordinal": target["ordinal"],
        "actor": "auditor", "reason": "历史大促订单，业务确认豁免"}).json()
    pp("豁免（绑定规则+样本摘要）", {k: ex[k] for k in
        ("rule_fingerprint", "sample_fingerprint", "table_name", "row_pk")})

    # 6) 冻结 revision 2（最新修订版）
    frozen = client.post(f"/products/{pid}/freeze").json()
    pp("冻结", {k: frozen[k] for k in
        ("revision", "status", "failure_count", "suppressed_count",
         "effective_count", "verdict", "credential_id")})

    # 7) 下载凭据并离线验签
    env = client.get(f"/products/{pid}/credentials/1/latest").json()
    pub_pem = client.get("/credentials/public-key").json()["public_key_pem"].encode()
    pub = serialization.load_pem_public_key(pub_pem)
    pub.verify(base64.b64decode(env["signature"]), canonical(env["body"]))
    pp("凭据下载并离线验签成功", {
        "credential_id": env["body"]["credential_id"],
        "rules_in_credential": len(env["body"]["rules"]),
        "exemptions_in_credential": len(env["body"]["active_exemptions"]),
        "db_file": db})

    # 8) 冻结后撤销豁免：凭据不可变
    client.post(f"/exemptions/{ex['exemption_id']}/revoke",
                json={"actor": "auditor", "reason": "事后撤销"})
    again = client.get(f"/products/{pid}/credentials/1/latest").json()
    assert again["signature"] == env["signature"]
    print("\n冻结后撤销豁免，凭据签名保持不变 ✔")


if __name__ == "__main__":
    main()
