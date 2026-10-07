"""裁决审计账本测试：

1. 全部规定动作都在同事务内追加不可改事件，字段与关联标识齐全；
2. 游标绑定固定读取起点，并发写入不丢/不重，重试同游标返回同一页；
3. 跨产品游标、非法游标、空范围、范围不一致均明确报错；
4. 按序号导出 JSON/CSV，且导出不改变业务数据与裁决状态；
5. 链验真：从任意起点重算，篡改任何字段/删除事件/伪造 prev 都精确报断点。
"""
from __future__ import annotations

import csv
import io
import json
import threading

from app.audit import decode_cursor, encode_cursor


def _pages(client, pid, page_size=2, start_time=None, end_time=None):
    """从首页翻到链尾，返回 (全部事件, 每页 seq 列表)。"""
    seen, pages, cursor = [], [], None
    while True:
        params = {"page_size": page_size}
        if cursor:
            params["cursor"] = cursor
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time
        page = client.get(f"/products/{pid}/audit/events", params=params)
        assert page.status_code == 200, page.text
        body = page.json()
        pages.append([e["seq"] for e in body["items"]])
        seen.extend(body["items"])
        cursor = body["next_cursor"]
        if not cursor:
            return seen, pages


def _all_events(client, pid, page_size=2, **kw):
    return _pages(client, pid, page_size, **kw)[0]


# ---------------------------------------------------------------------
# 1. 事件覆盖与字段
# ---------------------------------------------------------------------

def test_all_governed_actions_append_audit_events(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    rules = seeded["rules"]
    run1 = seeded["run_id"]

    # seeded 流程已产生：3 规则登记 + 1 修复 + 1 发布
    events = _all_events(c, pid)
    types = [e["event_type"] for e in events]
    assert types == (
        ["rule_registered"] * 3 + ["data_repaired", "adjudication_published"])
    assert [e["seq"] for e in events] == [1, 2, 3, 4, 5]

    # 首条事件：seq 连续、prev 为创世摘要，digest 为 64 位十六进制
    e1, e5 = events[0], events[-1]
    assert e1["prev_digest"] == "0" * 64
    assert len(e1["digest"]) == 64
    # 链引用：每条事件的 prev_digest 指向前一条
    for prev, cur in zip(events, events[1:]):
        assert cur["prev_digest"] == prev["digest"]
        assert cur["digest"] != prev["digest"]

    # 规则升级（v2 自动激活）后先回放形成修订，再把激活版切回 v1
    rng = rules["金额区间"]
    up = c.post(f"/rules/{rng}/versions", json={
        "product_id": pid, "name": "金额区间", "kind": "value_range",
        "config": {"table": "orders", "column": "amount", "min": 0, "max": 100},
        "actor": "ruleteam"})
    assert up.status_code == 201

    # 再次请求（回放）形成修订
    rp = c.post(f"/products/{pid}/replay", json={"actor": "carol"})
    assert rp.status_code == 201, rp.text
    rev2 = rp.json()

    act = c.post(f"/rules/{rng}/activate", json={"version": 1, "actor": "ruleteam"})
    assert act.status_code == 200

    # 豁免授予
    page = c.get(f"/runs/{run1}/failures").json()["items"]
    target = page[0]
    g = c.post("/exemptions", json={
        "run_id": run1, "ordinal": target["ordinal"],
        "actor": "auditor", "reason": "复核豁免"})
    assert g.status_code == 201
    ex_id = g.json()["exemption_id"]

    # 冻结 => 冻结事件 + 凭据签发事件
    fz = c.post(f"/products/{pid}/freeze", params={"actor": "compliance"})
    assert fz.status_code == 200

    # 豁免撤销
    rv = c.post(f"/exemptions/{ex_id}/revoke",
                json={"actor": "auditor", "reason": "复核撤销"})
    assert rv.status_code == 200

    events = _all_events(c, pid)
    by_type: dict[str, list] = {}
    for e in events:
        by_type.setdefault(e["event_type"], []).append(e)

    assert set(by_type) == {
        "rule_registered", "data_repaired", "adjudication_published",
        "rule_upgraded", "rule_activated", "revision_requested",
        "exemption_granted", "adjudication_frozen",
        "credential_issued", "exemption_revoked"}

    upgraded = by_type["rule_upgraded"][0]
    assert upgraded["actor"] == "ruleteam"
    assert upgraded["payload"]["version"] == 2
    assert upgraded["object_type"] == "rule" and upgraded["object_ref"] == rng

    rev_ev = by_type["revision_requested"][0]
    assert rev_ev["actor"] == "carol"
    assert rev_ev["data_version"] == 1 and rev_ev["revision"] == rev2["revision"]
    assert rev_ev["run_id"] == rev2["run_id"]

    grant_ev = by_type["exemption_granted"][0]
    assert grant_ev["run_id"] == run1
    assert grant_ev["payload"]["sample_fingerprint"] == target["sample_fingerprint"]
    assert grant_ev["payload"]["rule_fingerprint"] == target["rule_fingerprint"]

    frozen_ev = by_type["adjudication_frozen"][0]
    cred_ev = by_type["credential_issued"][0]
    assert frozen_ev["credential_id"] == cred_ev["credential_id"] == fz.json()["credential_id"]
    assert cred_ev["run_id"] == fz.json()["run_id"]
    assert cred_ev["payload"]["algorithm"] == "Ed25519"
    assert frozen_ev["actor"] == "compliance"
    # 两条事件在链上相邻（同一事务按序追加）
    assert cred_ev["prev_digest"] == frozen_ev["digest"]

    revoke_ev = by_type["exemption_revoked"][0]
    assert revoke_ev["actor"] == "auditor"
    assert revoke_ev["object_ref"] == ex_id
    assert revoke_ev["revision"] == 1 and revoke_ev["run_id"] == run1

    # 冻结幂等：重复冻结不再追加事件，也不签发新凭据
    n_before = len(events)
    c.post(f"/products/{pid}/freeze", params={"actor": "compliance"})
    assert len(_all_events(c, pid)) == n_before


def test_failed_write_does_not_append_audit_event(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    before = len(_all_events(c, pid))
    # 非法修复（类型不符）整事务回滚，审计事件随之回滚
    r = c.post(f"/products/{pid}/repair", json={
        "actor": "bob",
        "upserts": {"orders": [{"id": 9, "customer_id": 10, "amount": "x"}]}})
    assert r.status_code == 422
    # 对冻结裁决追加豁免被拒：同样不留审计痕迹
    c.post(f"/products/{pid}/freeze")
    r2 = c.post("/exemptions", json={
        "run_id": seeded["run_id"], "ordinal": 1,
        "actor": "late", "reason": "冻结后"})
    assert r2.status_code == 409
    after = _all_events(c, pid)
    # 只多了冻结事务的两条事件，失败的两次写入均未追加
    assert len(after) == before + 2


def test_audit_chain_is_append_only_by_default(seeded):
    """事件 seq 在产品内连续无空洞；不同产品链相互独立。"""
    c = seeded["client"]
    pid = seeded["product_id"]
    other = c.post("/products", json={
        "name": "另一产品",
        "tables": [{"name": "t", "pk_column": "id",
                    "columns": [{"name": "id", "type": "integer",
                                 "nullable": False}]}],
    }).json()["product_id"]
    c.post("/rules", json={
        "product_id": other, "name": "r", "kind": "not_null",
        "config": {"table": "t", "column": "id"}, "actor": "z"})

    ev_a = _all_events(c, pid)
    ev_b = _all_events(c, other)
    assert [e["seq"] for e in ev_a] == list(range(1, len(ev_a) + 1))
    assert [e["seq"] for e in ev_b] == [1]
    assert ev_b[0]["product_id"] == other and ev_a[0]["product_id"] == pid


# ---------------------------------------------------------------------
# 2. 游标：固定起点、并发安全、重试幂等
# ---------------------------------------------------------------------

def test_cursor_pagination_is_stable_under_concurrent_writes(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    rng = seeded["rules"]["金额区间"]

    # 先升级一次规则，让后续可以回放
    c.post(f"/rules/{rng}/versions", json={
        "product_id": pid, "name": "金额区间", "kind": "value_range",
        "config": {"table": "orders", "column": "amount", "min": 0, "max": 100}})

    # 首页固定
    p1 = c.get(f"/products/{pid}/audit/events", params={"page_size": 2}).json()
    assert [e["seq"] for e in p1["items"]] == [1, 2]
    cursor = p1["next_cursor"]
    assert decode_cursor(cursor)["after_seq"] == 2
    assert decode_cursor(cursor)["product_id"] == pid

    # 重试同一游标返回同一页（字节级一致）
    again = c.get(f"/products/{pid}/audit/events",
                  params={"page_size": 2, "cursor": cursor})
    assert again.json() == c.get(
        f"/products/{pid}/audit/events",
        params={"page_size": 2, "cursor": cursor}).json()
    assert [e["seq"] for e in again.json()["items"]] == [3, 4]

    # 翻页期间并发写入（产生新事件）：旧游标链既不丢也不重。
    # 用事件确定性地让“写入”发生在读者拿到第一页之后、继续翻页之前。
    first_page_done = threading.Event()
    writer_done = threading.Event()
    box = {}
    cur = encode_cursor(pid, after_seq=3, start_time=None, end_time=None, page_size=2)

    def churn():
        first_page_done.wait(timeout=5)
        c.post(f"/products/{pid}/replay", json={"actor": "t1"})
        c.post(f"/products/{pid}/freeze")
        c.post(f"/products/{pid}/repair", json={
            "actor": "t2",
            "upserts": {"orders": [
                {"id": 5, "customer_id": 10, "amount": 5, "status": "new",
                 "channel": "web"}]}})
        writer_done.set()

    def paged_read():
        got = []
        token = cur
        first = True
        while token:
            r = c.get(f"/products/{pid}/audit/events",
                      params={"page_size": 2, "cursor": token})
            assert r.status_code == 200, r.text
            body = r.json()
            got.extend(e["seq"] for e in body["items"])
            token = body["next_cursor"]
            if first:
                first = False
                first_page_done.set()
                writer_done.wait(timeout=5)  # 写入完成后再继续翻页
        box["seqs"] = got

    tw = threading.Thread(target=churn)
    tr = threading.Thread(target=paged_read)
    tr.start(); tw.start()
    tr.join(); tw.join()

    final = [e["seq"] for e in _all_events(c, pid)]
    # 游标从 seq>3 读起：并发写入发生在翻页中段，覆盖 4..N 连续区间，无重复无缺失
    assert sorted(box["seqs"]) == list(range(4, final[-1] + 1))
    assert len(box["seqs"]) == len(set(box["seqs"]))

    # 每页大小严格 <= page_size
    _, final_pages = _pages(c, pid, page_size=2)
    assert all(len(p) <= 2 for p in final_pages)


def test_invalid_and_cross_product_cursors_are_rejected(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    other = c.post("/products", json={
        "name": "另一产品",
        "tables": [{"name": "t", "pk_column": "id",
                    "columns": [{"name": "id", "type": "integer",
                                 "nullable": False}]}],
    }).json()["product_id"]
    c.post("/rules", json={
        "product_id": other, "name": "r", "kind": "not_null",
        "config": {"table": "t", "column": "id"}})

    # 非法游标：不是合法 base64token
    r = c.get(f"/products/{pid}/audit/events", params={"cursor": "%%%not-base64"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_cursor"
    # base64 可解但内容不是合法游标 JSON
    import base64 as _b64
    bogus = _b64.urlsafe_b64encode(b"not-a-cursor-json").decode().rstrip("=")
    r2 = c.get(f"/products/{pid}/audit/events", params={"cursor": bogus})
    assert r2.status_code == 400 and r2.json()["error"] == "invalid_cursor"
    # 结构字段缺失
    half = _b64.urlsafe_b64encode(b'{"p":"x"}').decode().rstrip("=")
    r3 = c.get(f"/products/{pid}/audit/events", params={"cursor": half})
    assert r3.status_code == 400 and r3.json()["error"] == "invalid_cursor"

    # 跨产品游标
    cur_pid = c.get(f"/products/{pid}/audit/events",
                    params={"page_size": 1}).json()["next_cursor"]
    cross = c.get(f"/products/{other}/audit/events",
                  params={"page_size": 1, "cursor": cur_pid})
    assert cross.status_code == 409
    assert cross.json()["error"] == "cursor_product_mismatch"

    # 游标绑定的时间范围与请求不一致
    cur_time = c.get(f"/products/{pid}/audit/events",
                     params={"page_size": 1,
                             "start_time": "2000-01-01T00:00:00Z"}).json()["next_cursor"]
    mismatch = c.get(f"/products/{pid}/audit/events",
                     params={"page_size": 1, "cursor": cur_time,
                             "start_time": "2001-01-01T00:00:00Z"})
    assert mismatch.status_code == 409
    assert mismatch.json()["error"] == "cursor_scope_mismatch"

    # page_size 非法
    bad_size = c.get(f"/products/{pid}/audit/events", params={"page_size": 0})
    assert bad_size.status_code == 422


def test_time_range_filter_and_empty_range(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    events = _all_events(c, pid)
    first_at = events[0]["occurred_at"]
    last_at = events[-1]["occurred_at"]

    # end_time = 末条事件时刻 => 末条被排除（半开区间）
    ranged = _all_events(c, pid, end_time=last_at)
    assert [e["seq"] for e in ranged] == list(range(1, len(events)))

    # start 取首条时刻（含） => 全部事件
    ranged2 = _all_events(c, pid, start_time=first_at)
    assert len(ranged2) == len(events)

    # 空范围明确错误
    r = c.get(f"/products/{pid}/audit/events",
              params={"start_time": "2999-01-01T00:00:00Z"})
    assert r.status_code == 404 and r.json()["error"] == "audit_empty_range"

    # 没有任何事件的产品首读也是空范围错误
    fresh = c.post("/products", json={
        "name": "空账本",
        "tables": [{"name": "t", "pk_column": "id",
                    "columns": [{"name": "id", "type": "integer"}]}],
    }).json()["product_id"]
    r2 = c.get(f"/products/{fresh}/audit/events")
    assert r2.status_code == 404 and r2.json()["error"] == "audit_empty_range"

    # 非法时间
    r3 = c.get(f"/products/{pid}/audit/events",
               params={"start_time": "not-a-time"})
    assert r3.status_code == 422 and r3.json()["error"] == "invalid_time_range"
    r4 = c.get(f"/products/{pid}/audit/events",
               params={"start_time": last_at, "end_time": first_at})
    assert r4.status_code == 422 and r4.json()["error"] == "invalid_time_range"


# ---------------------------------------------------------------------
# 3. 导出 JSON / CSV：只读、按序号、明确错误
# ---------------------------------------------------------------------

def test_export_json_and_csv_by_seq(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    total = len(_all_events(c, pid))

    j = c.get(f"/products/{pid}/audit/export",
              params={"start_seq": 2, "end_seq": 4})
    assert j.status_code == 200
    assert "attachment" in j.headers["content-disposition"]
    body = j.json()
    assert body["count"] == 3
    assert [e["seq"] for e in body["items"]] == [2, 3, 4]
    assert body["start_seq"] == 2 and body["end_seq"] == 4

    cv = c.get(f"/products/{pid}/audit/export", params={"fmt": "csv"})
    assert cv.status_code == 200
    assert cv.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(cv.text)))
    assert len(rows) == total
    assert list(rows[0].keys()) == [
        "product_id", "seq", "event_type", "object_type", "object_ref", "actor",
        "occurred_at", "data_version", "revision", "run_id", "credential_id",
        "prev_digest", "digest", "payload_json"]
    assert rows[0]["event_type"] == "rule_registered"
    # payload_json 是可解析的规范化 JSON
    payload = json.loads(rows[0]["payload_json"])
    assert payload["kind"] == "not_null"
    # 导出的链字段与分页接口一致
    paged = {e["seq"]: e for e in _all_events(c, pid)}
    for r in rows:
        assert r["digest"] == paged[int(r["seq"])]["digest"]

    # 非法格式 / 非法区间
    assert c.get(f"/products/{pid}/audit/export",
                 params={"fmt": "xml"}).status_code == 422
    assert c.get(f"/products/{pid}/audit/export",
                 params={"start_seq": 99999}).status_code == 404
    assert c.get(f"/products/{pid}/audit/export",
                 params={"start_seq": 3, "end_seq": 2}).status_code == 422
    assert c.get(f"/products/{pid}/audit/export",
                 params={"end_seq": 99999}).status_code == 422


def test_export_does_not_change_business_state(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    before_adj = c.get(f"/products/{pid}/adjudications").json()
    before_events = _all_events(c, pid)

    for _ in range(3):
        r = c.get(f"/products/{pid}/audit/export", params={"fmt": "json"})
        assert r.status_code == 200
        r2 = c.get(f"/products/{pid}/audit/export", params={"fmt": "csv"})
        assert r2.status_code == 200
        r3 = c.get(f"/products/{pid}/audit/verify")
        assert r3.status_code == 200

    after_adj = c.get(f"/products/{pid}/adjudications").json()
    after_events = _all_events(c, pid)
    assert before_adj == after_adj          # 裁决状态零变化
    assert before_events == after_events    # 账本零追加（导出不自审计）


# ---------------------------------------------------------------------
# 4. 链验真：任意起点 + 精确断点
# ---------------------------------------------------------------------

def test_verify_chain_valid_from_arbitrary_start(seeded):
    c = seeded["client"]
    pid = seeded["product_id"]
    events = _all_events(c, pid)
    n = len(events)

    full = c.get(f"/products/{pid}/audit/verify")
    assert full.status_code == 200
    b = full.json()
    assert b["valid"] is True and b["checked_events"] == n
    assert b["start_seq"] == 1 and b["end_seq"] == n
    assert b["chain_tip_digest"] == events[-1]["digest"]

    # 从任意起点重算：锚点是 start_seq-1 的已存摘要
    mid = c.get(f"/products/{pid}/audit/verify",
                params={"start_seq": 3, "end_seq": n - 1})
    assert mid.status_code == 200
    mb = mid.json()
    assert mb["checked_events"] == n - 3
    assert mb["chain_tip_digest"] == events[n - 2]["digest"]

    # 参数错误
    assert c.get(f"/products/{pid}/audit/verify",
                 params={"start_seq": 0}).status_code == 422
    assert c.get(f"/products/{pid}/audit/verify",
                 params={"start_seq": 9999}).status_code == 404
    assert c.get(f"/products/{pid}/audit/verify",
                 params={"end_seq": 9999}).status_code == 422
    fresh = c.post("/products", json={
        "name": "无链",
        "tables": [{"name": "t", "pk_column": "id",
                    "columns": [{"name": "id", "type": "integer"}]}],
    }).json()["product_id"]
    assert c.get(f"/products/{fresh}/audit/verify").status_code == 404


def _tamper_db(store, pid, seq, *, set_sql, params):
    with store.lock:
        store._conn.execute("BEGIN IMMEDIATE")
        try:
            store._conn.execute(set_sql, params)
            store._conn.execute("COMMIT")
        except Exception:
            store._conn.execute("ROLLBACK")
            raise


def test_verify_detects_field_tamper_with_exact_breakpoint(seeded):
    store = seeded["client"].store
    c = seeded["client"]
    pid = seeded["product_id"]

    # 篡改 seq=3 的 actor
    _tamper_db(
        store, pid, 3,
        set_sql="UPDATE audit_events SET actor='mallory' WHERE product_id=? AND seq=?",
        params=(pid, 3))
    r = c.get(f"/products/{pid}/audit/verify")
    assert r.status_code == 409
    d = r.json()["detail"]
    assert d["kind"] == "digest_mismatch" and d["seq"] == 3
    assert d["stored_digest"] != d["recomputed_digest"]

    # 从断点之后开始验：3 不在范围内，链环自身仍闭合（锚点是被污染的摘要）
    after = c.get(f"/products/{pid}/audit/verify", params={"start_seq": 4})
    assert after.status_code == 200
    # 从起点 1 验才能发现；从 2 开始也能发现（seq=3 在范围内）
    assert c.get(f"/products/{pid}/audit/verify",
                 params={"start_seq": 2}).status_code == 409


def test_verify_detects_payload_tamper(seeded):
    store = seeded["client"].store
    c = seeded["client"]
    pid = seeded["product_id"]
    # 直接改写 payload 内的值（保持合法 JSON）
    _tamper_db(
        store, pid, 4,
        set_sql="UPDATE audit_events SET payload_json=? "
                "WHERE product_id=? AND seq=?",
        params=(json.dumps({"note": "forged", "upserts": 99, "deletes": 0,
                            "base_version": 0, "repair_event_id": "x"},
                           sort_keys=True, separators=(",", ":")),
                pid, 4))
    r = c.get(f"/products/{pid}/audit/verify")
    assert r.status_code == 409
    d = r.json()["detail"]
    assert d["kind"] == "digest_mismatch" and d["seq"] == 4

    # 仅改 payload_json 的空白/键序（语义不变）不构成篡改：摘要按语义重算
    row = store._conn.execute(
        "SELECT payload_json FROM audit_events WHERE product_id=? AND seq=?",
        (pid, 5)).fetchone()
    obj = json.loads(row["payload_json"])
    _tamper_db(
        store, pid, 5,
        set_sql="UPDATE audit_events SET payload_json=? "
                "WHERE product_id=? AND seq=?",
        params=(json.dumps(obj, indent=4), pid, 5))
    # seq=4 已被污染，全链仍断；但从 seq=5 起验（锚点=4 的已存摘要），
    # seq=5 仅空白变化，按语义重算摘要一致 => 子链验真通过
    assert c.get(f"/products/{pid}/audit/verify",
                 params={"start_seq": 5}).status_code == 200
    assert c.get(f"/products/{pid}/audit/verify").status_code == 409


def test_verify_detects_deleted_event_gap(seeded):
    store = seeded["client"].store
    c = seeded["client"]
    pid = seeded["product_id"]
    # 删除中间事件（服务层无此路径，模拟带外破坏）
    _tamper_db(
        store, pid, 3,
        set_sql="DELETE FROM audit_events WHERE product_id=? AND seq=?",
        params=(pid, 3))
    r = c.get(f"/products/{pid}/audit/verify")
    assert r.status_code == 409
    d = r.json()["detail"]
    assert d["kind"] == "missing_event" and d["seq"] == 3

    # 从断点之后验：
    # - start_seq=4 时锚点是 seq=3 的事件（已删除）=> missing_event 报在 3；
    # - start_seq=5 时锚点 seq=4 完好，5..N 子链自身闭合（全链验真才是权威检查）。
    assert c.get(f"/products/{pid}/audit/verify",
                 params={"start_seq": 4}).status_code == 409
    assert c.get(f"/products/{pid}/audit/verify",
                 params={"start_seq": 5}).status_code == 200
    # 从缺失序号开始：首行已是 seq=4 => seq 空洞报在期望序号 3
    r3 = c.get(f"/products/{pid}/audit/verify", params={"start_seq": 3})
    assert r3.status_code == 409
    assert r3.json()["detail"]["kind"] == "missing_event"


def test_verify_detects_forged_prev_digest_and_genesis(seeded):
    store = seeded["client"].store
    c = seeded["client"]
    pid = seeded["product_id"]

    # 伪造首条事件的 prev_digest
    _tamper_db(
        store, pid, 1,
        set_sql="UPDATE audit_events SET prev_digest=? "
                "WHERE product_id=? AND seq=?",
        params=("a" * 64, pid, 1))
    r = c.get(f"/products/{pid}/audit/verify")
    assert r.status_code == 409
    d = r.json()["detail"]
    assert d["kind"] == "genesis_mismatch" and d["seq"] == 1

    # 伪造中间事件的 prev_digest（指向不存在的摘要）
    _tamper_db(
        store, pid, 1,
        set_sql="UPDATE audit_events SET prev_digest=? "
        "WHERE product_id=? AND seq=?",
        params=("0" * 64, pid, 1))
    _tamper_db(
        store, pid, 2,
        set_sql="UPDATE audit_events SET prev_digest=? "
        "WHERE product_id=? AND seq=?",
        params=("f" * 64, pid, 2))
    r2 = c.get(f"/products/{pid}/audit/verify")
    assert r2.status_code == 409
    d2 = r2.json()["detail"]
    assert d2["kind"] == "prev_digest_mismatch" and d2["seq"] == 2
    assert d2["stored_prev_digest"] == "f" * 64
    assert d2["expected_prev_digest"] != "f" * 64


def test_verify_anchor_before_missing_event(seeded):
    """从任意起点验真时，若锚点事件本身缺失，也要明确报断点。"""
    store = seeded["client"].store
    c = seeded["client"]
    pid = seeded["product_id"]
    _tamper_db(
        store, pid, 2,
        set_sql="DELETE FROM audit_events WHERE product_id=? AND seq=?",
        params=(pid, 2))
    r = c.get(f"/products/{pid}/audit/verify", params={"start_seq": 3})
    assert r.status_code == 409
    d = r.json()["detail"]
    assert d["kind"] == "missing_event" and d["seq"] == 2
