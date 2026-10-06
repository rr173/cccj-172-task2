"""合规复核裁决审计账本测试：

* 七类写操作各自追加不可修改事件，且同事务提交；
* 按产品+时间范围游标分页：固定起点、并发写入不丢不重、重试同页；
* CSV / JSON 导出按 seq 排序且绝不改变业务数据与裁决状态；
* 链验真：任意起点重算、篡改/删除被明确定位；
* 非法游标、跨产品游标、空范围返回明确错误；
* append-only：直接 UPDATE/DELETE 被引擎触发器拒绝。
"""
from __future__ import annotations

import csv
import io
import json
import sqlite3
import threading


def _walk(client, pid, page_size=2, **params):
    """走完整条审计游标链，返回 (事件列表, 各页 seq 列表)。"""
    events, pages, cursor = [], [], None
    while True:
        q = {"page_size": page_size, **params}
        if cursor:
            q["cursor"] = cursor
        r = client.get(f"/products/{pid}/audit", params=q)
        assert r.status_code == 200, r.text
        page = r.json()
        pages.append([e["seq"] for e in page["items"]])
        events.extend(page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            return events, pages


def _all(client, pid, **params):
    return _walk(client, pid, **params)[0]


# ---------------------------------------------------------------------
# 1. 七类业务操作全部留痕，序号每产品连续，链环相扣
# ---------------------------------------------------------------------

def test_every_mutation_appends_immutable_audit_event(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    rng_rule = seeded["rules"]["金额区间"]
    run1 = seeded["run_id"]

    # 建产品+3 规则登记 + 1 修复 + 1 发布 = 6 个初始事件
    initial = _all(c, pid)
    types0 = [e["event_type"] for e in initial]
    assert types0 == [
        "product_created",
        "rule_registered", "rule_registered", "rule_registered",
        "data_repaired", "adjudication_published",
    ]
    assert [e["seq"] for e in initial] == [1, 2, 3, 4, 5, 6]

    # 发布事件关联 data_version / revision / run
    pub_ev = initial[-1]
    assert pub_ev["data_version"] == 1
    assert pub_ev["revision"] == 1
    assert pub_ev["run_id"] == run1
    assert pub_ev["actor"] == "alice"

    # 规则升级
    up = c.post(f"/rules/{rng_rule}/versions", json={
        "product_id": pid, "name": "金额区间", "kind": "value_range",
        "config": {"table": "orders", "column": "amount", "min": 0, "max": 100}})
    assert up.status_code == 201

    # 再次请求形成修订（回放）
    rp = c.post(f"/products/{pid}/replay", json={"actor": "carol"})
    assert rp.status_code == 201
    run2 = rp.json()["run_id"]

    # 豁免授予
    f = c.get(f"/runs/{run2}/failures").json()["items"][0]
    g = c.post("/exemptions", json={
        "run_id": run2, "ordinal": f["ordinal"],
        "actor": "auditor", "reason": "合规豁免"})
    assert g.status_code == 201
    exmp_id = g.json()["exemption_id"]

    # 冻结 => adjudication_frozen + credential_issued 两个事件
    fz = c.post(f"/products/{pid}/freeze", params={"data_version": 1})
    assert fz.status_code == 200
    cred_id = fz.json()["credential_id"]

    # 豁免撤销
    rv = c.post(f"/exemptions/{exmp_id}/revoke",
                json={"actor": "auditor", "reason": "复核撤销"})
    assert rv.status_code == 200

    events = _all(c, pid)
    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    tail = [(e["event_type"], e["actor"]) for e in events[6:]]
    assert tail == [
        ("rule_upgraded", "system"),
        ("revision_requested", "carol"),
        ("exemption_granted", "auditor"),
        ("adjudication_frozen", "system"),
        ("credential_issued", "system"),
        ("exemption_revoked", "auditor"),
    ]

    rev_ev = next(e for e in events if e["event_type"] == "revision_requested")
    assert rev_ev["revision"] == 2 and rev_ev["run_id"] == run2
    assert rev_ev["detail"]["rule_versions"][rng_rule] == 2

    fr = next(e for e in events if e["event_type"] == "adjudication_frozen")
    ci = next(e for e in events if e["event_type"] == "credential_issued")
    assert fr["data_version"] == 1 and fr["revision"] == 2
    assert ci["credential_id"] == cred_id
    assert ci["run_id"] == run2
    assert fr["prev_digest"] == events[9 - 1]["digest"]
    assert ci["prev_digest"] == fr["digest"]
    assert ci["detail"]["algorithm"] == "Ed25519"

    revoke = next(e for e in events if e["event_type"] == "exemption_revoked")
    assert revoke["exemption_id"] == exmp_id

    # 首事件以空摘要为锚；之后环环相扣
    assert events[0]["prev_digest"] == ""
    for a, b in zip(events, events[1:]):
        assert b["prev_digest"] == a["digest"]
        assert len(a["digest"]) == 64


def test_freeze_idempotent_does_not_append_audit_events(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    c.post(f"/products/{pid}/freeze", params={"data_version": 1})
    n1 = len(_all(c, pid))
    c.post(f"/products/{pid}/freeze", params={"data_version": 1})
    n2 = len(_all(c, pid))
    assert n1 == n2  # 幂等再冻结不重复登记冻结/签发事件


def test_rule_activation_is_audited_but_same_version_is_noop(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    rng_rule = seeded["rules"]["金额区间"]
    before = len(_all(c, pid))
    # 激活当前版本（无变化）不追加事件
    r = c.post(f"/rules/{rng_rule}/activate", json={"version": 1})
    assert r.status_code == 200
    assert len(_all(c, pid)) == before
    # 先升级到 v2，再回退 v1，产生一次激活事件
    c.post(f"/rules/{rng_rule}/versions", json={
        "product_id": pid, "name": "金额区间", "kind": "value_range",
        "config": {"table": "orders", "column": "amount", "min": 0, "max": 100}})
    c.post(f"/rules/{rng_rule}/activate", json={"version": 1})
    types = [e["event_type"] for e in _all(c, pid)]
    assert types.count("rule_activated") == 1
    assert types[-1] == "rule_activated"


def test_audit_chains_are_independent_per_product(seeded):
    c = seeded["client"]
    other = c.post("/products", json={
        "name": "库存",
        "tables": [{"name": "items", "pk_column": "id", "columns": [
            {"name": "id", "type": "integer"}]}]}).json()["product_id"]
    ev_a = _all(c, seeded["product_id"])
    ev_b = _all(c, other)
    assert [e["seq"] for e in ev_b] == [1]           # 新产品链从 1 开始
    assert ev_b[0]["prev_digest"] == ""
    assert ev_b[0]["product_id"] == other
    assert ev_a[0]["digest"] != ev_b[0]["digest"]    # 链互不影响


# ---------------------------------------------------------------------
# 2. 游标：固定起点 / 并发不丢不重 / 重试同页
# ---------------------------------------------------------------------

def test_cursor_pagination_is_stable_and_gapless(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]

    page1 = c.get(f"/products/{pid}/audit", params={"page_size": 2}).json()
    assert [e["seq"] for e in page1["items"]] == [1, 2]
    assert page1["after_seq"] == 0
    cursor = page1["next_cursor"]
    assert cursor

    # 重试同一游标返回同一页
    again = c.get(f"/products/{pid}/audit",
                  params={"page_size": 2, "cursor": cursor}).json()
    first = [e["seq"] for e in again["items"]]
    assert first == [3, 4]
    retry = c.get(f"/products/{pid}/audit",
                  params={"page_size": 2, "cursor": cursor}).json()
    assert [e["seq"] for e in retry["items"]] == first

    # 翻页期间并发追加写入：既不丢也不重，序号连续
    seen: list[int] = []
    cursor_walk = page1["next_cursor"]
    for _ in range(2):
        r = c.post(f"/products/{pid}/repair", json={
            "actor": "concurrent",
            "upserts": {"orders": [
                {"id": 8, "customer_id": 10, "amount": 8,
                 "status": "new", "channel": "web"}]}})
        assert r.status_code == 200
        p = c.get(f"/products/{pid}/audit",
                  params={"page_size": 2, "cursor": cursor_walk}).json()
        seen.extend(e["seq"] for e in p["items"])
        cursor_walk = p["next_cursor"]

    all_events, pages = _walk(c, pid, page_size=2)
    seqs = [e["seq"] for e in all_events]
    assert seqs == list(range(1, len(seqs) + 1))     # 无缺号
    assert len(seqs) == len(set(seqs))               # 无重复
    # 每页都严格不超过 page_size
    assert all(len(p) <= 2 for p in pages)


def test_cursor_concurrent_writers_never_lose_events(seeded):
    """多线程混合写 + 同时从头游标读取：最终读到的事件数与写次数一致。"""
    c = seeded["client"]
    pid = seeded["product_id"]
    base = len(_all(c, pid))
    errors: list[Exception] = []

    def writer(n: int):
        try:
            for i in range(5):
                r = c.post(f"/products/{pid}/repair", json={
                    "actor": f"t{n}",
                    "upserts": {"orders": [
                        {"id": 100 + n * 10 + i, "customer_id": 10, "amount": 1,
                         "status": "new", "channel": "web"}]}})
                assert r.status_code == 200, r.text
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    events = _all(c, pid, page_size=3)
    seqs = [e["seq"] for e in events]
    assert seqs == list(range(1, len(seqs) + 1))
    assert len(events) == base + 20


def test_cursor_rejects_garbled_cross_product_and_scope_mismatch(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    other = c.post("/products", json={
        "name": "其他", "tables": [{"name": "t", "pk_column": "id",
                                    "columns": [{"name": "id", "type": "integer"}]}]
    }).json()["product_id"]

    p = c.get(f"/products/{pid}/audit", params={"page_size": 1}).json()
    cursor = p["next_cursor"]

    # 非法游标
    bad = c.get(f"/products/{pid}/audit",
                params={"page_size": 1, "cursor": "@@@not-base64@@@"})
    assert bad.status_code == 400
    assert bad.json()["error"] == "invalid_cursor"

    # 结构合法但内容伪造的游标
    import base64
    fake = base64.urlsafe_b64encode(
        json.dumps({"v": 9, "product_id": pid}).encode()).decode().rstrip("=")
    badver = c.get(f"/products/{pid}/audit",
                   params={"page_size": 1, "cursor": fake})
    assert badver.status_code == 400

    # 跨产品游标
    cross = c.get(f"/products/{other}/audit",
                  params={"page_size": 1, "cursor": cursor})
    assert cross.status_code == 409
    assert cross.json()["error"] == "cursor_product_mismatch"

    # 页大小不一致
    mis = c.get(f"/products/{pid}/audit",
                params={"page_size": 2, "cursor": cursor})
    assert mis.status_code == 409
    assert mis.json()["error"] == "cursor_scope_mismatch"

    # 时间范围与游标绑定不一致
    scoped = c.get(f"/products/{pid}/audit", params={
        "page_size": 1, "start_at": "2020-01-01T00:00:00Z"}).json()["next_cursor"]
    mis2 = c.get(f"/products/{pid}/audit", params={
        "page_size": 1, "cursor": scoped, "start_at": "2021-01-01T00:00:00Z"})
    assert mis2.status_code == 409
    assert mis2.json()["error"] == "cursor_scope_mismatch"


def test_time_range_filtering_and_empty_range_errors(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    all_events = _all(c, pid)
    first_ts, last_ts = all_events[0]["occurred_at"], all_events[-1]["occurred_at"]

    # [first, last) 排除最后一条
    mid = c.get(f"/products/{pid}/audit", params={
        "page_size": 100, "start_at": first_ts, "end_at": last_ts}).json()
    assert [e["seq"] for e in mid["items"]] == list(range(1, len(all_events)))

    # 起>=止 => 空范围明确报错
    err = c.get(f"/products/{pid}/audit", params={
        "start_at": last_ts, "end_at": first_ts})
    assert err.status_code == 422
    assert err.json()["error"] == "invalid_time_range"

    # 同一游标在时间范围内翻页稳定（范围不随追加扩张）
    p1 = c.get(f"/products/{pid}/audit", params={
        "page_size": 2, "start_at": first_ts, "end_at": last_ts}).json()
    p2 = c.get(f"/products/{pid}/audit", params={
        "page_size": 2, "cursor": p1["next_cursor"],
        "start_at": first_ts, "end_at": last_ts}).json()
    assert [e["seq"] for e in p2["items"]] == [3, 4]

    # 时间格式非法
    bad = c.get(f"/products/{pid}/audit",
                params={"start_at": "yesterday"})
    assert bad.status_code == 422
    assert bad.json()["error"] == "invalid_time_range"

    # 没有事件落在范围内 => 合法空页（不是空范围错误）
    empty = c.get(f"/products/{pid}/audit", params={
        "start_at": "2000-01-01T00:00:00Z", "end_at": "2000-02-01T00:00:00Z"})
    assert empty.status_code == 200
    assert empty.json()["items"] == []
    assert empty.json()["next_cursor"] is None


def test_audit_on_unknown_product_is_404(seeded):
    c = seeded["client"]
    r = c.get("/products/prd_nope/audit")
    assert r.status_code == 404
    assert r.json()["error"] == "product_not_found"


# ---------------------------------------------------------------------
# 3. 导出 CSV / JSON：按序号、纯只读
# ---------------------------------------------------------------------

def _adjudication_snapshot(c, pid):
    return c.get(f"/products/{pid}/adjudications",
                 params={"data_version": 1}).json()


def test_export_json_and_csv_are_read_only_and_ordered(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    before_adj = _adjudication_snapshot(c, pid)
    before = _all(c, pid)

    rj = c.get(f"/products/{pid}/audit/export", params={"format": "json"})
    assert rj.status_code == 200
    assert "attachment" in rj.headers["content-disposition"]
    doc = rj.json()
    assert doc["count"] == len(before)
    assert doc["tip_seq"] == before[-1]["seq"]
    assert doc["tip_digest"] == before[-1]["digest"]
    assert [e["seq"] for e in doc["events"]] == list(range(1, len(before) + 1))
    assert set(doc["events"][0]) >= {"prev_digest", "digest", "detail", "actor"}

    rc = c.get(f"/products/{pid}/audit/export", params={"format": "csv"})
    assert rc.status_code == 200
    assert rc.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(rc.text)))
    assert [int(r["seq"]) for r in rows] == list(range(1, len(before) + 1))
    assert rows[0]["prev_digest"] == ""
    # detail 是 JSON 文本，可还原
    assert json.loads(rows[0]["detail"])["name"] == "订单数据"

    # 时间范围导出
    rr = c.get(f"/products/{pid}/audit/export", params={
        "format": "json",
        "start_at": before[0]["occurred_at"],
        "end_at": before[-1]["occurred_at"]})
    assert rr.json()["count"] == len(before) - 1

    # 导出不改变业务数据、裁决状态，也不追加审计事件
    assert _adjudication_snapshot(c, pid) == before_adj
    after = _all(c, pid)
    assert after == before

    bad = c.get(f"/products/{pid}/audit/export", params={"format": "xml"})
    # FastAPI pattern 拦截 => 422
    assert bad.status_code == 422


# ---------------------------------------------------------------------
# 4. 链验真：任意起点 + 明确断点
# ---------------------------------------------------------------------

def test_verify_chain_valid_from_any_start(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]

    full = c.get(f"/products/{pid}/audit/verify")
    assert full.status_code == 200
    body = full.json()
    assert body["valid"] is True
    assert body["from_seq"] == 1
    assert body["checked"] == body["tip_seq"] >= 6
    assert body["break"] is None
    assert len(body["tip_digest"]) == 64

    mid = c.get(f"/products/{pid}/audit/verify", params={"from_seq": 3})
    assert mid.status_code == 200
    assert mid.json()["valid"] is True
    assert mid.json()["checked"] == body["tip_seq"] - 2


def test_verify_detects_tampered_event_content(seeded):
    c, pid, store = seeded["client"], seeded["product_id"], seeded["client"].store
    events = _all(c, pid)
    target_seq = 3
    original_digest = events[target_seq - 1]["digest"]

    # 触发器拒绝 UPDATE —— 用“停库直改”式验证：临时禁用触发器后篡改，再恢复。
    # 这模拟的是外部对库文件的离线篡改，验真必须抓出来。
    with store.tx(write=True) as conn:
        conn.execute("DROP TRIGGER trg_audit_no_update")
        conn.execute(
            "UPDATE audit_events SET actor='mallory' WHERE product_id=? AND seq=?",
            (pid, target_seq))

    r = c.get(f"/products/{pid}/audit/verify")
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert r.json()["error"] == "audit_chain_broken"
    assert detail["valid"] is False
    assert detail["break"]["seq"] == target_seq
    assert detail["break"]["reason"] == "digest_mismatch"
    assert detail["break"]["actual"] == original_digest
    assert detail["break"]["expected"] != original_digest
    assert "篡改" in detail["break"]["message"]

    # 从被篡改事件本身起步（锚点是其前驱 seq=2，未被篡改）：仍能发现
    r3 = c.get(f"/products/{pid}/audit/verify", params={"from_seq": target_seq})
    assert r3.status_code == 409
    assert r3.json()["detail"]["break"]["seq"] == target_seq

    # 从篡改点“之后”起步：seq=3 的已存摘要被当作可信锚点（from_seq 语义即
    # “信任此前链尾”），其后链接完好 => 该视角下 valid；
    # 全链/前驱视角的上面两次校验才会暴露篡改。
    r_later = c.get(f"/products/{pid}/audit/verify",
                    params={"from_seq": target_seq + 1})
    assert r_later.status_code == 200
    assert r_later.json()["valid"] is True


def test_verify_detects_deleted_event_gap(seeded):
    c, pid = seeded["client"], seeded["product_id"]
    with c.store.tx(write=True) as conn:
        conn.execute("DROP TRIGGER trg_audit_no_delete")
        conn.execute("DELETE FROM audit_events WHERE product_id=? AND seq=2", (pid,))

    r = c.get(f"/products/{pid}/audit/verify")
    assert r.status_code == 409
    br = r.json()["detail"]["break"]
    assert br["reason"] == "seq_gap"
    assert br["expected"] == 2 and br["actual"] == 3

    # 落在空洞之后的 from_seq：锚点缺失，明确报参数错误而非误判 valid
    r2 = c.get(f"/products/{pid}/audit/verify", params={"from_seq": 3})
    assert r2.status_code == 422
    assert r2.json()["error"] == "invalid_from_seq"


def test_verify_rejects_bad_from_seq(seeded):
    c, pid = seeded["client"], seeded["product_id"]
    r = c.get(f"/products/{pid}/audit/verify", params={"from_seq": 0})
    assert r.status_code == 422


# ---------------------------------------------------------------------
# 5. append-only：引擎层触发器拒绝任何 UPDATE / DELETE
# ---------------------------------------------------------------------

def test_audit_events_are_append_only_at_storage_layer(seeded):
    store, pid = seeded["client"].store, seeded["product_id"]
    with store.tx(write=True) as conn:
        try:
            conn.execute(
                "UPDATE audit_events SET actor='x' WHERE product_id=? AND seq=1",
                (pid,))
            raised = False
        except sqlite3.Error:
            raised = True
        assert raised, "UPDATE 审计事件必须被触发器拒绝"

        try:
            conn.execute("DELETE FROM audit_events WHERE product_id=? AND seq=1",
                         (pid,))
            raised_del = False
        except sqlite3.Error:
            raised_del = True
        assert raised_del, "DELETE 审计事件必须被触发器拒绝"

    # 数据完好
    events = _all(seeded["client"], pid)
    assert events[0]["actor"] != "x"
    assert len(events) >= 6


def test_audit_event_is_committed_in_same_transaction_as_business_write(seeded):
    """业务写入失败时不得留下孤儿审计事件（同事务回滚）。"""
    c = seeded["client"]
    pid = seeded["product_id"]
    before = len(_all(c, pid))
    # 触发业务校验失败（未知表）
    r = c.post(f"/products/{pid}/repair", json={
        "actor": "bob", "upserts": {"nope": [{"id": 1}]}})
    assert r.status_code == 422
    assert len(_all(c, pid)) == before
