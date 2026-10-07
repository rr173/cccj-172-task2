"""面向合规复核的裁决审计账本。

* **仅追加哈希链**：每一次数据修复、规则登记/升级/激活、发布裁决、
  回放修订、豁免授予/撤销、冻结、凭据签发，都在同一写事务内追加一条
  ``audit_events``。链按产品独立编号，``seq`` 在产品内从 1 连续递增，
  每条事件携带前一事件摘要，本事件摘要覆盖事件全部字段（含 prev_digest）。
* **游标固定读取起点**：游标是 base64 的
  ``{product_id, after_seq, start_time, end_time, page_size}``，读取按
  ``(product_id, seq)`` keyset 翻页。账本只追加，期间并发写入既不会让
  翻页丢事件或重复事件，重试同一游标也始终返回同一页。
* **验真**：可从任意 ``start_seq`` 重算摘要链，逐链环核对
  prev_digest / 本事件摘要 / seq 连续性，明确指出断点序号与断点类型。
"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .errors import DomainError
from .storage import Store

#: 账本格式版本（写入 canonical 串，升级哈希规则时可区分）
AUDIT_VERSION = "1.0"
#: 每个产品首条事件的前一事件摘要
GENESIS_DIGEST = "0" * 64
MAX_PAGE_SIZE = 200
MAX_EXPORT_ROWS = 100_000


# ---------------------------------------------------------------------
# 摘要
# ---------------------------------------------------------------------

def canonical_event(row: dict[str, Any], prev_digest: str) -> bytes:
    """构造参与摘要计算的规范化串。

    payload 以解析后对象放入（Store.dumps 会再次 sort_keys 规范化），
    因此即便有人改动 payload_json 的空白/键序，摘要也保持一致；
    而改动 payload 内任何值都会改变摘要。
    """
    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    obj = {
        "version": AUDIT_VERSION,
        "product_id": row["product_id"],
        "seq": row["seq"],
        "event_type": row["event_type"],
        "object_type": row["object_type"],
        "object_ref": row["object_ref"],
        "actor": row["actor"],
        "occurred_at": row["occurred_at"],
        "data_version": row["data_version"],
        "revision": row["revision"],
        "run_id": row["run_id"],
        "credential_id": row["credential_id"],
        "payload": payload,
        "prev_digest": prev_digest,
    }
    return Store.dumps(obj).encode("utf-8")


def compute_digest(row: dict[str, Any], prev_digest: str) -> str:
    return hashlib.sha256(canonical_event(row, prev_digest)).hexdigest()


# ---------------------------------------------------------------------
# 仅追加写入（必须在调用方已持有的写事务连接上执行）
# ---------------------------------------------------------------------

def append_event(
    conn: sqlite3.Connection,
    *,
    product_id: str,
    event_type: str,
    object_type: str,
    object_ref: str,
    actor: str,
    occurred_at: str,
    payload: dict[str, Any],
    data_version: int | None = None,
    revision: int | None = None,
    run_id: str | None = None,
    credential_id: str | None = None,
) -> dict[str, Any]:
    """在当前事务内追加一条审计事件；与业务写入同提交或同回滚。"""
    last = conn.execute(
        "SELECT seq, digest FROM audit_events WHERE product_id=? ORDER BY seq DESC LIMIT 1",
        (product_id,)).fetchone()
    seq = (last["seq"] + 1) if last is not None else 1
    prev_digest = last["digest"] if last is not None else GENESIS_DIGEST
    payload_json = Store.dumps(payload)
    row = {
        "product_id": product_id,
        "seq": seq,
        "event_type": event_type,
        "object_type": object_type,
        "object_ref": object_ref,
        "actor": actor,
        "occurred_at": occurred_at,
        "data_version": data_version,
        "revision": revision,
        "run_id": run_id,
        "credential_id": credential_id,
        "payload": payload,
    }
    digest = compute_digest(row, prev_digest)
    conn.execute(
        "INSERT INTO audit_events(product_id,seq,event_type,object_type,object_ref,"
        "actor,occurred_at,data_version,revision,run_id,credential_id,payload_json,"
        "prev_digest,digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (product_id, seq, event_type, object_type, object_ref, actor, occurred_at,
         data_version, revision, run_id, credential_id, payload_json,
         prev_digest, digest))
    row["payload"] = payload_json  # 与落库形态保持一致
    row["prev_digest"] = prev_digest
    row["digest"] = digest
    return row


# ---------------------------------------------------------------------
# 时间参数与游标
# ---------------------------------------------------------------------

def parse_time(value: str | None) -> str | None:
    """把 ISO-8601 入参规范化为可与 occurred_at 字典比较的 UTC 微秒串。"""
    if value is None:
        return None
    v = value.strip()
    try:
        if v.endswith(("Z", "z")):
            dt = datetime.fromisoformat(v[:-1] + "+00:00")
        else:
            dt = datetime.fromisoformat(v)
    except ValueError:
        raise DomainError(422, "invalid_time_range",
                          f"无法解析时间参数: {value!r}（需要 ISO-8601，如 2026-10-07T00:00:00Z）")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def encode_cursor(product_id: str, *, after_seq: int, start_time: str | None,
                  end_time: str | None, page_size: int) -> str:
    token = {"p": product_id, "a": after_seq, "ps": page_size,
             "s": start_time, "e": end_time}
    return _b64e(Store.dumps(token).encode("utf-8"))


def decode_cursor(cursor: str) -> dict[str, Any]:
    try:
        token = json.loads(_b64d(cursor))
    except Exception:
        raise DomainError(400, "invalid_cursor", "游标无法解析")
    if not isinstance(token, dict) or not isinstance(token.get("p"), str) \
            or not isinstance(token.get("a"), int) or not isinstance(token.get("ps"), int):
        raise DomainError(400, "invalid_cursor", "游标内容不完整")
    return {"product_id": token["p"], "after_seq": token["a"],
            "page_size": token["ps"], "start_time": token.get("s"),
            "end_time": token.get("e")}


# ---------------------------------------------------------------------
# 读取模型
# ---------------------------------------------------------------------

EVENT_COLUMNS = (
    "product_id", "seq", "event_type", "object_type", "object_ref", "actor",
    "occurred_at", "data_version", "revision", "run_id", "credential_id",
    "payload_json", "prev_digest", "digest",
)


def event_out(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "product_id": r["product_id"],
        "seq": r["seq"],
        "event_type": r["event_type"],
        "object_type": r["object_type"],
        "object_ref": r["object_ref"],
        "actor": r["actor"],
        "occurred_at": r["occurred_at"],
        "data_version": r["data_version"],
        "revision": r["revision"],
        "run_id": r["run_id"],
        "credential_id": r["credential_id"],
        "payload": json.loads(r["payload_json"]),
        "prev_digest": r["prev_digest"],
        "digest": r["digest"],
    }


def _validate_time_window(start_time: str | None, end_time: str | None) -> None:
    if start_time is not None and end_time is not None and end_time <= start_time:
        raise DomainError(422, "invalid_time_range",
                          "end_time 必须晚于 start_time")


def _query_rows(conn: sqlite3.Connection, product_id: str, *,
                after_seq: int, start_time: str | None, end_time: str | None,
                limit: int) -> list[sqlite3.Row]:
    where = ["product_id=?", "seq>?"]
    params: list[Any] = [product_id, after_seq]
    if start_time is not None:
        where.append("occurred_at>=?")
        params.append(start_time)
    if end_time is not None:
        where.append("occurred_at<?")
        params.append(end_time)
    params.append(limit)
    return list(conn.execute(
        f"SELECT {', '.join(EVENT_COLUMNS)} FROM audit_events "
        f"WHERE {' AND '.join(where)} ORDER BY seq ASC LIMIT ?", params))


class AuditLedger:
    """审计账本读取/导出/验真（写入见 :func:`append_event`）。"""

    def __init__(self, store: Store):
        self.store = store

    def _require_product(self, conn: sqlite3.Connection, product_id: str) -> None:
        if conn.execute("SELECT 1 FROM products WHERE product_id=?",
                        (product_id,)).fetchone() is None:
            raise DomainError(404, "product_not_found", product_id)

    # ----- 游标分页 -------------------------------------------------------

    def read_page(self, product_id: str, *, cursor: str | None = None,
                  page_size: int = 50, start_time: str | None = None,
                  end_time: str | None = None) -> dict[str, Any]:
        if page_size < 1 or page_size > MAX_PAGE_SIZE:
            raise DomainError(422, "invalid_page_size",
                              f"page_size 须在 1..{MAX_PAGE_SIZE}")
        start_time = parse_time(start_time)
        end_time = parse_time(end_time)
        _validate_time_window(start_time, end_time)

        if cursor is None:
            after_seq = 0
        else:
            tok = decode_cursor(cursor)
            if tok["product_id"] != product_id:
                raise DomainError(409, "cursor_product_mismatch",
                                  "游标属于另一个产品，审计账本不可跨产品分页")
            if tok["start_time"] != start_time or tok["end_time"] != end_time:
                raise DomainError(409, "cursor_scope_mismatch",
                                  "游标绑定的时间范围与请求不一致；请用首次请求的范围")
            after_seq = tok["after_seq"]
            page_size = tok["page_size"]

        with self.store.tx() as conn:  # 单读事务 = 固定账本快照
            self._require_product(conn, product_id)
            rows = _query_rows(conn, product_id, after_seq=after_seq,
                               start_time=start_time, end_time=end_time,
                               limit=page_size + 1)

        page = rows[:page_size]
        # 首次请求（after_seq=0）范围为空 -> 明确错误；游标请求返回空页只代表翻到链尾
        if cursor is None and not page:
            raise DomainError(404, "audit_empty_range",
                              "该产品在指定时间范围内没有任何审计事件")
        next_cursor = None
        if len(rows) > page_size:
            next_cursor = encode_cursor(
                product_id, after_seq=page[-1]["seq"],
                start_time=start_time, end_time=end_time, page_size=page_size)
        return {
            "product_id": product_id,
            "page_size": page_size,
            "start_time": start_time,
            "end_time": end_time,
            "after_seq": after_seq,
            "next_cursor": next_cursor,
            "items": [event_out(r) for r in page],
            "snapshot_note": (
                "账本仅追加：游标绑定固定读取起点 (product_id, after_seq, 时间范围)，"
                "期间并发写入不会让翻页丢事件或重复事件，重试同一游标返回同一页"),
        }

    # ----- 按序号导出（只读，绝不触碰业务数据与裁决状态） -----------------

    def export(self, product_id: str, *, start_seq: int = 1,
               end_seq: int | None = None, fmt: str = "json") -> \
            tuple[list[dict[str, Any]], str]:
        if fmt not in ("json", "csv"):
            raise DomainError(422, "invalid_format", "fmt 仅支持 json / csv")
        if start_seq < 1:
            raise DomainError(422, "invalid_range", "start_seq 必须 >= 1")
        if end_seq is not None and end_seq < start_seq:
            raise DomainError(422, "invalid_range", "end_seq 不可小于 start_seq")
        with self.store.tx() as conn:
            self._require_product(conn, product_id)
            max_seq = conn.execute(
                "SELECT MAX(seq) AS m FROM audit_events WHERE product_id=?",
                (product_id,)).fetchone()["m"]
            if max_seq is None:
                raise DomainError(404, "audit_empty_range", "该产品尚无审计事件")
            if end_seq is not None and end_seq > max_seq:
                raise DomainError(422, "invalid_range",
                                  {"end_seq": end_seq, "max_seq": max_seq})
            hi = end_seq if end_seq is not None else max_seq
            if hi - start_seq + 1 > MAX_EXPORT_ROWS:
                raise DomainError(
                    422, "range_too_large",
                    f"单次导出上限 {MAX_EXPORT_ROWS} 条，请缩小序号区间分段导出")
            rows = list(conn.execute(
                f"SELECT {', '.join(EVENT_COLUMNS)} FROM audit_events "
                "WHERE product_id=? AND seq BETWEEN ? AND ? ORDER BY seq ASC",
                (product_id, start_seq, hi)))
        if not rows:
            raise DomainError(404, "audit_empty_range",
                              {"start_seq": start_seq, "end_seq": hi})
        return [event_out(r) for r in rows], fmt

    # ----- 链验真 ---------------------------------------------------------

    def verify_chain(self, product_id: str, *, start_seq: int = 1,
                     end_seq: int | None = None) -> dict[str, Any]:
        """从 start_seq 重算摘要链并核对链环。

        断点类型：
        * ``missing_event``   —— seq 空洞（事件被删除）；
        * ``prev_digest_mismatch`` —— 存储的 prev_digest 与重算的上一链环不符；
        * ``digest_mismatch`` —— 事件字段被篡改导致摘要不符；
        * ``genesis_mismatch`` —— 首条事件的 prev_digest 不是创世摘要。
        """
        if start_seq < 1:
            raise DomainError(422, "invalid_range", "start_seq 必须 >= 1")
        if end_seq is not None and end_seq < start_seq:
            raise DomainError(422, "invalid_range", "end_seq 不可小于 start_seq")

        def broken(kind: str, seq: int, detail: dict[str, Any]) -> DomainError:
            return DomainError(409, "audit_chain_broken",
                               {"kind": kind, "seq": seq, **detail})

        with self.store.tx() as conn:
            self._require_product(conn, product_id)
            max_seq = conn.execute(
                "SELECT MAX(seq) AS m FROM audit_events WHERE product_id=?",
                (product_id,)).fetchone()["m"]
            if max_seq is None:
                raise DomainError(404, "audit_empty_range", "该产品尚无审计事件")
            if start_seq > max_seq:
                raise DomainError(404, "audit_empty_range",
                                  {"start_seq": start_seq, "max_seq": max_seq})
            if end_seq is not None and end_seq > max_seq:
                raise DomainError(422, "invalid_range",
                                  {"end_seq": end_seq, "max_seq": max_seq})
            hi = end_seq if end_seq is not None else max_seq

            # 起点锚点：start_seq 之前一条事件的摘要（start_seq=1 时为创世摘要）
            if start_seq == 1:
                expected_prev = GENESIS_DIGEST
            else:
                anchor = conn.execute(
                    "SELECT seq, digest FROM audit_events "
                    "WHERE product_id=? AND seq=?",
                    (product_id, start_seq - 1)).fetchone()
                if anchor is None:
                    raise broken(
                        "missing_event", start_seq - 1,
                        {"expected_seq": start_seq - 1,
                         "note": "验真起点的锚点事件不存在，链在此之前已断裂"})
                expected_prev = anchor["digest"]

            rows = list(conn.execute(
                f"SELECT {', '.join(EVENT_COLUMNS)} FROM audit_events "
                "WHERE product_id=? AND seq BETWEEN ? AND ? ORDER BY seq ASC",
                (product_id, start_seq, hi)))

        checked = 0
        expected_seq = start_seq
        for r in rows:
            if r["seq"] != expected_seq:
                raise broken("missing_event", expected_seq,
                             {"expected_seq": expected_seq,
                              "found_seq": r["seq"]})
            stored_prev = r["prev_digest"]
            if stored_prev != expected_prev:
                kind = "genesis_mismatch" if expected_seq == 1 and expected_prev == GENESIS_DIGEST \
                    else "prev_digest_mismatch"
                raise broken(kind, r["seq"],
                             {"stored_prev_digest": stored_prev,
                              "expected_prev_digest": expected_prev})
            recomputed = compute_digest(
                {"product_id": r["product_id"], "seq": r["seq"],
                 "event_type": r["event_type"], "object_type": r["object_type"],
                 "object_ref": r["object_ref"], "actor": r["actor"],
                 "occurred_at": r["occurred_at"], "data_version": r["data_version"],
                 "revision": r["revision"], "run_id": r["run_id"],
                 "credential_id": r["credential_id"],
                 "payload": r["payload_json"]},
                expected_prev)
            if recomputed != r["digest"]:
                raise broken("digest_mismatch", r["seq"],
                             {"stored_digest": r["digest"],
                              "recomputed_digest": recomputed})
            expected_prev = r["digest"]
            expected_seq += 1
            checked += 1

        if checked != hi - start_seq + 1:
            raise broken("missing_event", expected_seq,
                         {"expected_seq": expected_seq, "checked": checked})

        return {
            "valid": True,
            "product_id": product_id,
            "start_seq": start_seq,
            "end_seq": hi,
            "checked_events": checked,
            "chain_tip_digest": expected_prev,
            "algorithm": f"sha256(canonical:v{AUDIT_VERSION})",
        }
