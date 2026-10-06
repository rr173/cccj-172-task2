"""测试夹具：每个用例独立内存库 + 已初始化的基础场景。

基础场景（orders 产品）：
  - orders(id, customer_id NOT NULL, amount, status)
  - customers(id, name)
  - 规则：R_NN orders.customer_id 非空
         R_RNG orders.amount 0..1000
         R_FK orders.customer_id -> customers.id
  - 初始发布 v1 含若干失败行
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.storage import Store


@pytest.fixture
def client():
    store = Store(":memory:")
    app = create_app(store)
    with TestClient(app) as c:
        c.store = store
        yield c


@pytest.fixture
def seeded(client) -> dict:
    r = client.post("/products", json={
        "name": "订单数据",
        "tables": [
            {"name": "orders", "pk_column": "id", "columns": [
                {"name": "id", "type": "integer", "nullable": False},
                {"name": "customer_id", "type": "integer", "nullable": True},
                {"name": "amount", "type": "number", "nullable": True},
                {"name": "status", "type": "string", "nullable": True},
                {"name": "channel", "type": "string", "nullable": False},
            ]},
            {"name": "customers", "pk_column": "id", "columns": [
                {"name": "id", "type": "integer", "nullable": False},
                {"name": "name", "type": "string", "nullable": True},
            ]},
        ],
    })
    pid = r.json()["product_id"]

    rules = {}
    for body in [
        {"product_id": pid, "name": "订单必须有客户", "kind": "not_null",
         "config": {"table": "orders", "column": "customer_id"}},
        {"product_id": pid, "name": "金额区间", "kind": "value_range",
         "config": {"table": "orders", "column": "amount", "min": 0, "max": 1000}},
        {"product_id": pid, "name": "订单客户必须存在", "kind": "cross_table",
         "config": {"left_table": "orders", "left_columns": ["customer_id"],
                    "right_table": "customers", "right_columns": ["id"]}},
    ]:
        rr = client.post("/rules", json=body)
        assert rr.status_code == 201, rr.text
        rules[body["name"]] = rr.json()["rule_id"]

    rep = client.post(f"/products/{pid}/repair", json={
        "actor": "alice", "note": "初始装载",
        "upserts": {
            "orders": [
                {"id": 1, "customer_id": 10, "amount": 100, "status": "paid",
                 "channel": "web"},
                {"id": 2, "customer_id": None, "amount": 5000, "status": "new",
                 "channel": "web"},
                {"id": 3, "customer_id": 99, "amount": 50, "status": "new",
                 "channel": "app"},
            ],
            "customers": [{"id": 10, "name": "张三"}],
        },
    })
    assert rep.status_code == 200, rep.text
    pub = client.post(f"/products/{pid}/publish", json={"actor": "alice"})
    assert pub.status_code == 201, pub.text
    v1 = pub.json()
    return {"client": client, "product_id": pid, "rules": rules,
            "run_id": v1["run_id"], "data_version": 1, "adjudication": v1}
