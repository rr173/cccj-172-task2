"""端到端语义测试：快照、版本化、回放修订版、冻结、豁免、分页、凭据。"""
from __future__ import annotations

import base64
import json
import threading

from cryptography.hazmat.primitives import serialization


def _all_failures(client, run_id, page_size=2):
    """翻完整个失败游标链。"""
    items, cursor = [], None
    seen_run = None
    while True:
        params = {"page_size": page_size}
        if cursor:
            params["cursor"] = cursor
        page = client.get(f"/runs/{run_id}/failures", params=params).json()
        assert page["run_id"] == run_id
        seen_run = page["run_id"]
        items.extend(page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            return items


# ---------------------------------------------------------------------
# 1. 发布快照固定：修复不改变历史版本
# ---------------------------------------------------------------------

def test_publish_creates_immutable_snapshot_and_adjudication(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    adj = seeded["adjudication"]
    assert adj["data_version"] == 1
    assert adj["revision"] == 1
    assert adj["status"] == "open"
    assert adj["trigger"] == "publish"

    failures = _all_failures(c, seeded["run_id"])
    # id2: not_null + out_of_range；id3: 孤儿外键
    assert len(failures) == 3
    assert {f["table_name"] + ":" + f["row_pk"] for f in failures} == {
        "orders:2", "orders:2", "orders:3"}
    # 每条失败都记录规则版本与规则摘要
    for f in failures:
        assert f["rule_version"] >= 1
        assert len(f["rule_fingerprint"]) == 64
        assert len(f["sample_fingerprint"]) == 64

    # 修复数据（删掉坏行）后发布 v2；v1 的 run_failures 不受影响
    c.post(f"/products/{pid}/repair", json={
        "actor": "bob",
        "upserts": {"orders": [{"id": 2, "customer_id": 10, "amount": 5000, "status": "new"}]},
        "deletes": {},
    })
    # 暂存区是全量的；再把金额修正
    c.post(f"/products/{pid}/repair", json={
        "actor": "bob",
        "upserts": {"orders": [{"id": 2, "customer_id": 10, "amount": 500, "status": "paid"}]},
    })
    c.post(f"/products/{pid}/repair", json={
        "actor": "bob",
        "upserts": {"orders": [{"id": 3, "customer_id": 10, "amount": 50, "status": "paid"}]},
    })
    pub2 = c.post(f"/products/{pid}/publish", json={"actor": "bob"}).json()
    assert pub2["data_version"] == 2
    assert pub2["revision"] == 1
    assert pub2["failure_count"] == 0
    assert pub2["verdict"] == "pass"

    # v1 失败样本仍然是 3 条 —— 历史发布判断没有被数据修复覆盖
    old = _all_failures(c, seeded["run_id"])
    assert len(old) == 3


def test_publish_without_changes_is_rejected(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    r = c.post(f"/products/{pid}/publish", json={"actor": "alice"})
    assert r.status_code == 409
    assert r.json()["error"] == "no_changes_since_last_version"


def test_repair_cannot_mutate_published_rows(seeded):
    """修复行类型/非空约束在暂存区被拦截。"""
    c = seeded["client"]
    pid = seeded["product_id"]
    r = c.post(f"/products/{pid}/repair", json={
        "actor": "bob",
        "upserts": {"orders": [{"id": 9, "customer_id": 10, "amount": "x"}]},
    })
    assert r.status_code == 422
    assert r.json()["error"] == "type_mismatch"
    r2 = c.post(f"/products/{pid}/repair", json={
        "actor": "bob",
        "upserts": {"orders": [{"id": 9, "amount": 10}]},  # channel NOT NULL
    })
    assert r2.status_code == 422
    assert r2.json()["error"] == "not_null_violation_in_repair"


# ---------------------------------------------------------------------
# 2. 规则升级 + 历史快照回放 => 只产生新修订版
# ---------------------------------------------------------------------

def test_rule_upgrade_and_replay_creates_revision_without_overwriting(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    rng_rule = seeded["rules"]["金额区间"]

    before = c.get(f"/rules/{rng_rule}").json()
    assert before["active_version"] == 1

    # 升级：收紧区间到 [0, 100]
    up = c.post(f"/rules/{rng_rule}/versions", json={
        "product_id": pid, "name": "金额区间", "kind": "value_range",
        "config": {"table": "orders", "column": "amount", "min": 0, "max": 100},
    })
    assert up.status_code == 201
    assert up.json()["active_version"] == 2
    v2fp = up.json()["versions"][1]["fingerprint"]
    v1fp = up.json()["versions"][0]["fingerprint"]
    assert v1fp != v2fp

    # 相同定义重复升级被拒绝
    dup = c.post(f"/rules/{rng_rule}/versions", json={
        "product_id": pid, "name": "金额区间", "kind": "value_range",
        "config": {"table": "orders", "column": "amount", "min": 0, "max": 100},
    })
    assert dup.status_code == 409

    # 不允许改变规则类型
    bad = c.post(f"/rules/{rng_rule}/versions", json={
        "product_id": pid, "name": "金额区间", "kind": "not_null",
        "config": {"table": "orders", "column": "amount"},
    })
    assert bad.status_code == 422

    # 回放 v1 快照 => revision 2；revision 1 原样保留
    rp = c.post(f"/products/{pid}/replay", json={"actor": "carol"})
    assert rp.status_code == 201, rp.text
    rev2 = rp.json()
    assert rev2["data_version"] == 1
    assert rev2["revision"] == 2
    assert rev2["trigger"] == "replay"
    # 新区间 [0,100] 闭区间：id1(100)、id3(50) 均在界内，只有 id2(5000) 越界；
    # 失败集合仍是 id2×2 + id3 外键，但区间规则携带的是新指纹
    assert rev2["failure_count"] == 3
    run2 = rev2["run_id"]
    fps = {f["rule_fingerprint"] for f in _all_failures(c, run2)}
    assert v2fp in fps
    assert v1fp not in fps

    # 修订版 1 的结论与 run 完全未被触碰
    adj_list = c.get(f"/products/{pid}/adjudications",
                     params={"data_version": 1}).json()
    assert [a["revision"] for a in adj_list] == [1, 2]
    rev1 = adj_list[0]
    assert rev1["status"] == "open"
    fps1 = {f["rule_fingerprint"] for f in _all_failures(c, seeded["run_id"])}
    assert v1fp in fps1

    # 同一规则集再次回放被拒绝（回放必须包含规则变化）
    again = c.post(f"/products/{pid}/replay", json={"actor": "carol"})
    assert again.status_code == 409
    assert again.json()["error"] == "ruleset_already_adjudicated"

    # 发布之后新增一条规则，再回放历史快照：新规则组合此前不存在，允许回放。
    # 这正是"规则升级后对历史快照回放"的常见姿势。
    st = c.post("/rules", json={
        "product_id": pid, "name": "状态非空", "kind": "not_null",
        "config": {"table": "orders", "column": "status"}})
    assert st.status_code == 201
    status_rule = st.json()["rule_id"]
    # 当前激活集 = rng v2 + nn v1 + fk v1 + status_nn v1
    rev3 = c.post(f"/products/{pid}/replay", json={"actor": "carol"})
    assert rev3.status_code == 201, rev3.text
    rev3 = rev3.json()
    assert rev3["revision"] == 3
    assert rev3["ruleset_fingerprint"] not in {
        a["ruleset_fingerprint"] for a in adj_list}
    assert rev3["run_id"] not in {seeded["run_id"], rev2["run_id"]}

    # 混合版本回放：区间规则回退 v1，其余保持当前 => 又一个全新规则集
    mixed = {r["rule_id"]: r["active_version"]
             for r in c.get(f"/products/{pid}/rules").json()}
    mixed[rng_rule] = 1
    hist2 = c.post(f"/products/{pid}/replay", json={
        "actor": "carol", "rule_versions": mixed})
    assert hist2.status_code == 201, hist2.text
    rev4 = hist2.json()
    assert rev4["revision"] == 4
    # rev4 的失败里区间规则是 v1 指纹，新状态规则同样参与
    rev4_fps = {f["rule_fingerprint"] for f in _all_failures(c, rev4["run_id"])}
    assert v1fp in rev4_fps
    assert v2fp not in rev4_fps

    # 不存在的规则版本在回放入口被拒绝
    bogus = c.post(f"/products/{pid}/replay", json={
        "actor": "carol", "rule_versions": {status_rule: 99}})
    assert bogus.status_code == 404

    # 最终修订版链完整，历史 revision 1/2 的 run 从未被改写
    final = c.get(f"/products/{pid}/adjudications",
                  params={"data_version": 1}).json()
    assert [a["revision"] for a in final] == [1, 2, 3, 4]
    assert [a["run_id"] for a in final[:2]] == [seeded["run_id"], run2]


def test_replay_requires_published_snapshot(seeded):
    c = seeded["client"]
    # 全新空产品没有快照
    p = c.post("/products", json={
        "name": "空",
        "tables": [{"name": "t", "pk_column": "id",
                    "columns": [{"name": "id", "type": "integer"}]}],
    }).json()
    r = c.post(f"/products/{p['product_id']}/replay", json={"actor": "z"})
    assert r.status_code == 404


# ---------------------------------------------------------------------
# 3. 冻结：发布判断不可变 + 可下载可验证凭据
# ---------------------------------------------------------------------

def test_freeze_materializes_judgment_and_credential(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    run_id = seeded["run_id"]

    # 先对一条失败授予豁免（id3 的外键失败）
    failures = _all_failures(c, run_id)
    fk_failure = next(f for f in failures
                      if f["table_name"] == "orders" and f["row_pk"] == "3")
    g = c.post("/exemptions", json={
        "run_id": run_id, "ordinal": fk_failure["ordinal"],
        "actor": "auditor", "reason": "客户记录延迟入库，已确认"})
    assert g.status_code == 201, g.text

    adj = c.get(f"/products/{pid}/adjudications",
                params={"data_version": 1}).json()[0]
    assert adj["suppressed_count"] == 1
    assert adj["effective_count"] == 2
    assert adj["verdict"] == "fail"

    # 冻结
    fz = c.post(f"/products/{pid}/freeze", params={"data_version": 1})
    assert fz.status_code == 200
    frozen = fz.json()
    assert frozen["status"] == "frozen"
    assert frozen["suppressed_count"] == 1
    assert frozen["effective_count"] == 2
    assert frozen["frozen_at"] is not None
    cred_id = frozen["credential_id"]
    assert cred_id

    # 冻结后再撤销豁免 —— 冻结结论与凭据不得改变
    ex = c.get(f"/products/{pid}/exemptions",
               params={"data_version": 1}).json()["items"][0]
    rv = c.post(f"/exemptions/{ex['exemption_id']}/revoke",
                json={"actor": "auditor", "reason": "复核撤销"})
    assert rv.status_code == 200

    adj_after = c.get(f"/products/{pid}/adjudications",
                      params={"data_version": 1}).json()[0]
    assert adj_after["status"] == "frozen"
    assert adj_after["suppressed_count"] == 1       # 物化值不变
    assert adj_after["effective_count"] == 2
    assert adj_after["verdict"] == "fail"

    # 冻结后不得追加豁免（针对该 run 的失败）
    another = next(f for f in failures if f["ordinal"] != fk_failure["ordinal"])
    denied = c.post("/exemptions", json={
        "run_id": run_id, "ordinal": another["ordinal"],
        "actor": "auditor", "reason": "迟到的豁免"})
    assert denied.status_code == 409
    assert denied.json()["error"] == "adjudication_frozen"

    # 冻结幂等：再次冻结返回同一凭据
    fz2 = c.post(f"/products/{pid}/freeze", params={"data_version": 1}).json()
    assert fz2["credential_id"] == cred_id

    # 下载凭据
    dl = c.get(f"/products/{pid}/credentials/1/1")
    assert dl.status_code == 200
    assert "attachment" in dl.headers["content-disposition"]
    envelope = dl.json()
    body, signature = envelope["body"], envelope["signature"]
    assert body["credential_id"] == cred_id
    assert body["verdict"] == "fail"
    assert body["failure_count"] == 3
    assert body["suppressed_count"] == 1
    assert len(body["rules"]) == 3   # 规则集完整存档（含零失败之外的全部规则）
    assert len(body["active_exemptions"]) == 1
    assert body["active_exemptions"][0]["row_pk"] == "3"

    # 公钥验签通过
    pub_pem = c.get("/credentials/public-key").json()["public_key_pem"].encode()
    pub = serialization.load_pem_public_key(pub_pem)
    canon = json.dumps(body, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")).encode()
    pub.verify(base64.b64decode(signature), canon)  # 不抛异常即通过

    # 平台验签端点
    ok = c.post("/credentials/verify", json={"body": body, "signature": signature})
    assert ok.json()["valid"] is True

    # 篡改正文 -> 验签失败
    tampered = dict(body)
    tampered["verdict"] = "pass"
    bad = c.post("/credentials/verify",
                 json={"body": tampered, "signature": signature})
    assert bad.status_code == 400
    assert bad.json()["valid"] is False

    # 未冻结修订版不能下载
    dlerr = c.get(f"/products/{pid}/credentials/1/2")
    # revision 2 尚不存在（本用例没有回放）
    assert dlerr.status_code in (404, 409)


def test_freeze_always_latest_revision(seeded):
    """回放后冻结的是最新修订版；旧修订版必须先单独冻结才有凭据。"""
    c = seeded["client"]
    pid = seeded["product_id"]
    rng_rule = seeded["rules"]["金额区间"]
    c.post(f"/rules/{rng_rule}/versions", json={
        "product_id": pid, "name": "金额区间", "kind": "value_range",
        "config": {"table": "orders", "column": "amount", "min": 0, "max": 100}})
    c.post(f"/products/{pid}/replay", json={"actor": "carol"})

    fz = c.post(f"/products/{pid}/freeze", params={"data_version": 1}).json()
    assert fz["revision"] == 2
    assert fz["trigger"] == "replay"
    # revision 1 仍开放
    rev1 = c.get(f"/products/{pid}/adjudications",
                 params={"data_version": 1}).json()[0]
    assert rev1["revision"] == 1 and rev1["status"] == "open"

    latest = c.get(f"/products/{pid}/credentials/1/latest").json()
    assert latest["body"]["revision"] == 2
    rev1dl = c.get(f"/products/{pid}/credentials/1/1")
    assert rev1dl.status_code == 409  # 未冻结


# ---------------------------------------------------------------------
# 4. 豁免绑定精确样本 + 规则摘要
# ---------------------------------------------------------------------

def test_exemption_binds_to_exact_sample_and_rule_fingerprint(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    rng_rule = seeded["rules"]["金额区间"]
    run_id = seeded["run_id"]
    failures = _all_failures(c, run_id)
    range_failure = next(
        f for f in failures
        if f["detail"].get("reason") == "out_of_range")

    # 对 v1 规则下 id2 的区间失败授予豁免
    g = c.post("/exemptions", json={
        "run_id": run_id, "ordinal": range_failure["ordinal"],
        "actor": "auditor", "reason": "历史数据口径豁免"})
    assert g.status_code == 201
    ex = g.json()
    assert ex["sample_fingerprint"] == range_failure["sample_fingerprint"]
    assert ex["rule_fingerprint"] == range_failure["rule_fingerprint"]

    # 同一样本同一规则重复授予 -> 409（部分唯一索引）
    again = c.post("/exemptions", json={
        "run_id": run_id, "ordinal": range_failure["ordinal"],
        "actor": "auditor", "reason": "再来一次"})
    assert again.status_code == 409
    assert again.json()["error"] == "exemption_exists"

    # 升级规则（指纹变化）后回放：旧豁免不抑制新 run 的同样本失败
    c.post(f"/rules/{rng_rule}/versions", json={
        "product_id": pid, "name": "金额区间", "kind": "value_range",
        "config": {"table": "orders", "column": "amount", "min": 0, "max": 100}})
    rev2 = c.post(f"/products/{pid}/replay", json={"actor": "carol"}).json()
    new_failures = _all_failures(c, rev2["run_id"])
    new_range = next(f for f in new_failures
                     if f["detail"].get("reason") == "out_of_range")
    assert new_range["rule_fingerprint"] != ex["rule_fingerprint"]
    assert new_range["suppressed"] is False
    assert new_range["suppression"] is None

    # 旧 run（revision 1）的同位置失败仍处于豁免抑制状态
    old_range = next(f for f in _all_failures(c, run_id)
                     if f["detail"].get("reason") == "out_of_range")
    assert old_range["suppressed"] is True
    assert old_range["suppression"]["reason"] == "历史数据口径豁免"

    # 豁免工作台只对精确行/规则生效：id3 的失败不被抑制
    fk = next(f for f in _all_failures(c, run_id) if f["row_pk"] == "3")
    assert fk["suppressed"] is False


def test_exemption_ttl_expiry(seeded):
    c = seeded["client"]
    run_id = seeded["run_id"]
    failures = _all_failures(c, run_id)
    f = failures[0]
    g = c.post("/exemptions", json={
        "run_id": run_id, "ordinal": f["ordinal"],
        "actor": "a", "reason": "临时", "ttl_seconds": 1})
    assert g.status_code == 201
    assert g.json()["expires_at"] is not None

    import time
    time.sleep(1.1)
    again = _all_failures(c, run_id)
    target = next(x for x in again if x["ordinal"] == f["ordinal"])
    assert target["suppressed"] is False


def test_grant_on_bad_ordinal(seeded):
    c = seeded["client"]
    r = c.post("/exemptions", json={
        "run_id": seeded["run_id"], "ordinal": 999,
        "actor": "a", "reason": "x"})
    assert r.status_code == 404


def test_revoke_then_regrant_same_sample(seeded):
    """撤销后可重新授予同 (规则,样本)；撤销可重复操作报 409。"""
    c = seeded["client"]
    run_id = seeded["run_id"]
    f = _all_failures(c, run_id)[0]
    g = c.post("/exemptions", json={
        "run_id": run_id, "ordinal": f["ordinal"],
        "actor": "a", "reason": "first"}).json()
    c.post(f"/exemptions/{g['exemption_id']}/revoke", json={"actor": "a"})
    dup_revoke = c.post(f"/exemptions/{g['exemption_id']}/revoke",
                        json={"actor": "a"})
    assert dup_revoke.status_code == 409

    g2 = c.post("/exemptions", json={
        "run_id": run_id, "ordinal": f["ordinal"],
        "actor": "b", "reason": "second"})
    assert g2.status_code == 201
    assert g2.json()["exemption_id"] != g["exemption_id"]

    rows = c.get(f"/products/{seeded['product_id']}/exemptions",
                 params={"data_version": 1, "status": "active"}).json()
    assert len(rows["items"]) == 1
    assert rows["items"][0]["reason"] == "second"


# ---------------------------------------------------------------------
# 5. 分页：只能读取固定结果快照
# ---------------------------------------------------------------------

def test_pagination_cursor_is_bound_to_run_snapshot(seeded):
    c = seeded["client"]
    run_id = seeded["run_id"]
    other_run = _make_second_run(c, seeded)

    # 拿到第一页游标
    page1 = c.get(f"/runs/{run_id}/failures", params={"page_size": 1}).json()
    cursor = page1["next_cursor"]
    assert cursor

    # 游标不能跨 run 使用
    cross = c.get(f"/runs/{other_run}/failures",
                  params={"page_size": 1, "cursor": cursor})
    assert cross.status_code == 409
    assert cross.json()["error"] == "cursor_snapshot_mismatch"

    # 串页读取结果稳定（即使此刻发生豁免写入，失败行集合不变）
    all1 = _all_failures(c, run_id, page_size=1)
    f = all1[0]
    c.post("/exemptions", json={
        "run_id": run_id, "ordinal": f["ordinal"],
        "actor": "a", "reason": "分页期间写入豁免"})
    all2 = _all_failures(c, run_id, page_size=1)
    assert [x["ordinal"] for x in all1] == [x["ordinal"] for x in all2]
    # 仅抑制标记发生变化（豁免是同一 run 内的合法裁决动作）
    assert all2[0]["suppressed"] is True

    # 伪造游标被拒绝
    bad = c.get(f"/runs/{run_id}/failures",
                params={"cursor": "not-a-token!!"})
    assert bad.status_code in (400, 422)


def _make_second_run(client, seeded) -> str:
    pid = seeded["product_id"]
    rng_rule = seeded["rules"]["金额区间"]
    client.post(f"/rules/{rng_rule}/versions", json={
        "product_id": pid, "name": "金额区间", "kind": "value_range",
        "config": {"table": "orders", "column": "amount", "min": 0, "max": 100}})
    rev2 = client.post(f"/products/{pid}/replay", json={"actor": "x"}).json()
    return rev2["run_id"]


# ---------------------------------------------------------------------
# 6. 并发：修复 / 回放 / 冻结 / 豁免 交错不产生脏状态
# ---------------------------------------------------------------------

def test_concurrent_mixed_writes_are_serialized(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    rng_rule = seeded["rules"]["金额区间"]
    run_id = seeded["run_id"]
    failures = _all_failures(c, run_id)
    ordinals = [f["ordinal"] for f in failures]

    errors: list = []

    def upgrade_and_replay():
        try:
            r = c.post(f"/rules/{rng_rule}/versions", json={
                "product_id": pid, "name": "金额区间", "kind": "value_range",
                "config": {"table": "orders", "column": "amount",
                           "min": 0, "max": 200}})
            # 若另一线程已升级，改用激活版回放
            assert r.status_code in (201, 409)
            rr = c.post(f"/products/{pid}/replay", json={"actor": "t1"})
            assert rr.status_code in (201, 409), rr.text
        except Exception as e:  # pragma: no cover
            errors.append(e)

    def grant_exemptions():
        try:
            for o in ordinals:
                r = c.post("/exemptions", json={
                    "run_id": run_id, "ordinal": o,
                    "actor": "t2", "reason": f"并发豁免 {o}"})
                assert r.status_code in (201, 409), r.text
        except Exception as e:  # pragma: no cover
            errors.append(e)

    def repair_data():
        try:
            r = c.post(f"/products/{pid}/repair", json={
                "actor": "t3",
                "upserts": {"orders": [
                    {"id": 7, "customer_id": 10, "amount": 70,
                     "status": "new", "channel": "web"}]}})
            assert r.status_code == 200, r.text
        except Exception as e:  # pragma: no cover
            errors.append(e)

    def freeze():
        try:
            r = c.post(f"/products/{pid}/freeze", params={"data_version": 1})
            assert r.status_code == 200, r.text
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=fn) for fn in
               (upgrade_and_replay, grant_exemptions, repair_data, freeze)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    # 冻结裁决恰好一个、revision 链连续（冻结 rev1 后回放产生 rev2 是合法交错）
    adjs = c.get(f"/products/{pid}/adjudications",
                 params={"data_version": 1}).json()
    assert [a["revision"] for a in adjs] == list(range(1, len(adjs) + 1))
    frozen = [a for a in adjs if a["status"] == "frozen"]
    assert len(frozen) == 1
    frozen_rev = frozen[0]["revision"]

    # 已冻结修订版必有凭据，计数自洽且可验签
    dl = c.get(f"/products/{pid}/credentials/1/{frozen_rev}").json()
    body, sig = dl["body"], dl["signature"]
    verify = c.post("/credentials/verify", json={"body": body, "signature": sig})
    assert verify.json()["valid"] is True
    assert body["failure_count"] - body["suppressed_count"] == body["effective_count"]

    # 冻结之后任何针对该 run 的豁免写入都被拒绝
    r = c.post("/exemptions", json={
        "run_id": frozen[0]["run_id"], "ordinal": 1,
        "actor": "late", "reason": "冻结后"})
    assert r.status_code == 409

    # 回放产生的较新 open 修订版仍可独立冻结（不覆盖既有冻结）
    if frozen_rev != adjs[-1]["revision"]:
        fz = c.post(f"/products/{pid}/freeze", params={"data_version": 1})
        second = fz.json()
        assert second["revision"] == adjs[-1]["revision"]
        assert second["status"] == "frozen"
        both = c.get(f"/products/{pid}/adjudications",
                     params={"data_version": 1}).json()
        assert len([a for a in both if a["status"] == "frozen"]) == 2
        # 旧冻结的凭据不可变
        old_dl = c.get(f"/products/{pid}/credentials/1/{frozen_rev}").json()
        assert old_dl["body"]["credential_id"] == body["credential_id"]


# ---------------------------------------------------------------------
# 7. 规则定义校验
# ---------------------------------------------------------------------

def test_rule_definition_validation(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    # 引用不存在的表
    r = c.post("/rules", json={
        "product_id": pid, "name": "x", "kind": "not_null",
        "config": {"table": "nope", "column": "a"}})
    assert r.status_code == 422
    # 缺配置
    r2 = c.post("/rules", json={
        "product_id": pid, "name": "x", "kind": "value_range",
        "config": {"table": "orders", "column": "amount"}})
    assert r2.status_code == 422
    # 跨表外键规则正常
    r3 = c.post("/rules", json={
        "product_id": pid, "name": "状态自洽", "kind": "cross_field",
        "config": {"table": "orders", "left": "amount", "op": "ge", "right": "amount"}})
    assert r3.status_code == 201


# ---------------------------------------------------------------------
# 8. 规则引擎单元：各规则类型失败定位正确
# ---------------------------------------------------------------------

def test_engine_unique_and_cross_field(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    # 再造一个产品独立验证 unique / cross_field
    p = c.post("/products", json={
        "name": "库存",
        "tables": [{"name": "items", "pk_column": "id", "columns": [
            {"name": "id", "type": "integer", "nullable": False},
            {"name": "sku", "type": "string", "nullable": True},
            {"name": "qty", "type": "integer", "nullable": True},
            {"name": "reserved", "type": "integer", "nullable": True}]}]})
    ip = p.json()["product_id"]
    u = c.post("/rules", json={
        "product_id": ip, "name": "sku 唯一", "kind": "unique",
        "config": {"table": "items", "columns": ["sku"]}}).json()["rule_id"]
    cf = c.post("/rules", json={
        "product_id": ip, "name": "预留不超库存", "kind": "cross_field",
        "config": {"table": "items", "left": "reserved",
                   "op": "le", "right": "qty"}}).json()["rule_id"]
    c.post(f"/products/{ip}/repair", json={"actor": "a", "upserts": {"items": [
        {"id": 1, "sku": "S1", "qty": 10, "reserved": 3},
        {"id": 2, "sku": "S1", "qty": 5, "reserved": 9},
        {"id": 3, "sku": None, "qty": 2, "reserved": 1}]}})
    pub = c.post(f"/products/{ip}/publish", json={"actor": "a"}).json()
    failures = _all_failures(c, pub["run_id"])
    reasons = {(f["rule_id"], f["row_pk"], f["detail"]["reason"]) for f in failures}
    assert (u, "2", "duplicate") in reasons
    assert (cf, "2", "comparison_failed") in reasons
    # sku NULL 不算重复
    assert not any(f["row_pk"] == "3" for f in failures)
