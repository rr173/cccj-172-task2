"""合规复核裁决审计账本：只追加、按产品独立成链。

每条审计事件的摘要链为::

    payload   = canonical({事件全部业务字段})
    digest[1] = SHA256(prev_digest="" + payload)          # 每产品链锚点
    digest[n] = SHA256(prev_digest=digest[n-1] + payload)

约束：

* ``seq`` 在每个产品内从 1 开始单调递增，与业务写操作在**同一事务**内分配，
  串行化的写事务保证既不跳号也不重号；
* ``audit_events`` 上的触发器在 SQLite 引擎层拒绝 UPDATE / DELETE，
  事件一旦追加即不可修改（合规要求）；
* 读侧为键集分页（``seq > after_seq``）：事件只追加、序号永不复用，
  因此翻页期间的并发写入既不会让页之间丢事件，也不会重复事件；
* 游标令牌绑定产品、时间范围、页大小与读取起点，跨产品/跨范围立即拒绝。
"""
from __future__ import annotations

import hashlib
import sqlite3
from typing import Any, Sequence

from .storage import Store

#: 允许登记的事件类型（数据修复 / 规则登记、升级、激活 / 发布裁决 /
#: 再次请求形成修订 / 豁免授予、撤销 / 冻结 / 凭据签发）
EVENT_TYPES: frozenset[str] = frozenset({
    "product_created",
    "data_repaired",
    "adjudication_published",
    "rule_registered",
    "rule_upgraded",
    "rule_activated",
    "revision_requested",
    "exemption_granted",
    "exemption_revoked",
    "adjudication_frozen",
    "credential_issued",
})

GENESIS_DIGEST = ""

#: detail_json 之外的全部业务字段（参与摘要计算，顺序无关——canonical 排序）
_PAYLOAD_KEYS: tuple[str, ...] = (
    "product_id", "seq", "event_id", "event_type",
    "object_type", "object_id", "actor", "occurred_at",
    "data_version", "revision", "run_id", "credential_id",
    "exemption_id", "rule_id", "detail",
)


class AuditError(ValueError):
    """调用方构造了非法审计事件（未知类型等），属于编程错误。"""


def digest_event(fields: dict[str, Any], prev_digest: str) -> str:
    """按 canonical JSON 计算单条事件摘要（与验真接口重算逻辑完全一致）。

    链摘要格式::

        SHA256(prev_digest_hex + "\\n" + canonical_payload_utf8)

    首事件 ``prev_digest`` 为空串（每产品独立锚点）。
    """
    payload = {k: fields.get(k) for k in _PAYLOAD_KEYS}
    canon = Store.dumps(payload).encode("utf-8")
    return hashlib.sha256(prev_digest.encode("ascii") + b"\n" + canon).hexdigest()


def _check_event_type(event_type: str) -> None:
    if event_type not in EVENT_TYPES:
        raise AuditError(f"unknown audit event_type: {event_type!r}")


class AuditLedger:
    """审计账本写入/读取/验真；无状态，所有方法都在调用方给定连接上执行。"""

    # ---- 写入（必须位于调用方的 BEGIN IMMEDIATE 事务内） ------------------

    @staticmethod
    def append(conn: sqlite3.Connection, *, product_id: str, event_type: str,
               object_type: str, actor: str, occurred_at: str,
               object_id: str | None = None,
               data_version: int | None = None,
               revision: int | None = None,
               run_id: str | None = None,
               credential_id: str | None = None,
               exemption_id: str | None = None,
               rule_id: str | None = None,
               detail: dict[str, Any] | None = None,
               event_id: str | None = None) -> dict[str, Any]:
        """在当前写事务内追加一条不可修改事件，返回落库字段。

        ``seq`` 与链摘要都在事务内即时计算，与业务行原子提交。
        """
        _check_event_type(event_type)
        row = Store.qone(
            conn,
            "SELECT COALESCE(MAX(seq),0) AS m FROM audit_events WHERE product_id=?",
            (product_id,))
        seq = row["m"] + 1
        prev = Store.qone(
            conn,
            "SELECT digest FROM audit_events WHERE product_id=? AND seq=?",
            (product_id, seq - 1))
        prev_digest = prev["digest"] if prev is not None else GENESIS_DIGEST

        fields: dict[str, Any] = {
            "product_id": product_id,
            "seq": seq,
            "event_id": event_id or f"aud_{seq:010d}_{hashlib.sha1((product_id + occurred_at + event_type).encode()).hexdigest()[:10]}",
            "event_type": event_type,
            "object_type": object_type,
            "object_id": object_id,
            "actor": actor,
            "occurred_at": occurred_at,
            "data_version": data_version,
            "revision": revision,
            "run_id": run_id,
            "credential_id": credential_id,
            "exemption_id": exemption_id,
            "rule_id": rule_id,
            "detail": detail or {},
        }
        fields["prev_digest"] = prev_digest
        fields["digest"] = digest_event(fields, prev_digest)

        conn.execute(
            "INSERT INTO audit_events(product_id,seq,event_id,event_type,object_type,"
            "object_id,actor,occurred_at,data_version,revision,run_id,credential_id,"
            "exemption_id,rule_id,detail_json,prev_digest,digest)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (product_id, seq, fields["event_id"], event_type, object_type, object_id,
             actor, occurred_at, data_version, revision, run_id, credential_id,
             exemption_id, rule_id, Store.dumps(fields["detail"]),
             prev_digest, fields["digest"]))
        return fields

    # ---- 读取 -------------------------------------------------------------

    @staticmethod
    def tip(conn: sqlite3.Connection, product_id: str) -> dict[str, Any] | None:
        r = Store.qone(
            conn,
            "SELECT seq,digest FROM audit_events WHERE product_id=? ORDER BY seq DESC LIMIT 1",
            (product_id,))
        return {"seq": r["seq"], "digest": r["digest"]} if r else None

    @staticmethod
    def read_page(conn: sqlite3.Connection, product_id: str, *,
                  after_seq: int, limit: int,
                  start_at: str | None = None,
                  end_at: str | None = None) -> list[sqlite3.Row]:
        """键集分页：严格按 seq 升序读取 seq > after_seq 的事件。

        时间范围为半开区间 [start_at, end_at)。序号永不复用、事件只追加，
        故无论读事务跨越多少并发写入，页与页之间都不会丢/重事件。
        """
        where = ["product_id=?", "seq > ?"]
        params: list[Any] = [product_id, after_seq]
        if start_at is not None:
            where.append("occurred_at >= ?")
            params.append(start_at)
        if end_at is not None:
            where.append("occurred_at < ?")
            params.append(end_at)
        params.append(limit)
        return Store.qall(
            conn,
            f"SELECT * FROM audit_events WHERE {' AND '.join(where)} ORDER BY seq LIMIT ?",
            params)

    @staticmethod
    def read_range(conn: sqlite3.Connection, product_id: str, *,
                   start_at: str | None = None,
                   end_at: str | None = None,
                   from_seq: int = 1,
                   limit: int | None = None) -> list[sqlite3.Row]:
        """导出用：按时间范围 + 起始序号读取（不加时间过滤时为全链）。"""
        where = ["product_id=?", "seq >= ?"]
        params: list[Any] = [product_id, from_seq]
        if start_at is not None:
            where.append("occurred_at >= ?")
            params.append(start_at)
        if end_at is not None:
            where.append("occurred_at < ?")
            params.append(end_at)
        sql = (f"SELECT * FROM audit_events WHERE {' AND '.join(where)} ORDER BY seq")
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        return Store.qall(conn, sql, params)

    # ---- 验真 -------------------------------------------------------------

    @staticmethod
    def verify_chain(conn: sqlite3.Connection, product_id: str, *,
                     from_seq: int = 1) -> dict[str, Any]:
        """从任意起点重算摘要链，返回链状态与第一个明确断点。

        * ``from_seq=1``：以空摘要为锚，校验整条链；
        * ``from_seq>1``：锚点为 from_seq-1 的已存摘要，校验其后的链接关系，
          同时仍会发现 seq 缺号（删除行）；
        * 返回 ``{"valid", "from_seq", "tip_seq", "tip_digest",
          "checked", "break"}``；断点 break 含 seq / reason / expected / actual。
        """
        if not isinstance(from_seq, int) or from_seq < 1:
            raise ValueError("from_seq 必须为 >=1 的整数")

        anchor_seq = from_seq - 1
        if anchor_seq > 0:
            anchor = Store.qone(
                conn, "SELECT digest FROM audit_events WHERE product_id=? AND seq=?",
                (product_id, anchor_seq))
            if anchor is None:
                # 锚点本身缺失：起点不能落在空洞之后
                raise ValueError(f"锚点事件 seq={anchor_seq} 不存在，无法从 {from_seq} 起验链")
            expected_prev = anchor["digest"]
        else:
            expected_prev = GENESIS_DIGEST

        rows = Store.qall(
            conn,
            "SELECT * FROM audit_events WHERE product_id=? AND seq>=? ORDER BY seq",
            (product_id, from_seq))

        checked = 0
        expected_seq = from_seq
        break_info: dict[str, Any] | None = None
        last_digest = expected_prev

        for r in rows:
            if break_info is None and r["seq"] != expected_seq:
                break_info = {
                    "seq": expected_seq,
                    "reason": "seq_gap",
                    "expected": expected_seq,
                    "actual": r["seq"],
                    "message": f"事件序号不连续：期望 seq={expected_seq}，实际跳至 seq={r['seq']}"
                               "（疑似事件被删除）",
                }
                # 出现空洞后无法继续链接校验，直接报告
                break
            fields = _row_to_fields(r)
            recomputed = digest_event(fields, r["prev_digest"])
            if break_info is None and r["prev_digest"] != expected_prev:
                break_info = {
                    "seq": r["seq"],
                    "reason": "prev_digest_mismatch",
                    "expected": expected_prev,
                    "actual": r["prev_digest"],
                    "message": f"seq={r['seq']} 的前一事件摘要与重算链不一致（链在此处断开）",
                }
            if break_info is None and recomputed != r["digest"]:
                break_info = {
                    "seq": r["seq"],
                    "reason": "digest_mismatch",
                    "expected": recomputed,
                    "actual": r["digest"],
                    "message": f"seq={r['seq']} 的事件摘要重算不一致（事件内容疑似被篡改）",
                }
            expected_prev = r["digest"]
            last_digest = r["digest"]
            expected_seq += 1
            checked += 1

        tip = AuditLedger.tip(conn, product_id)
        return {
            "valid": break_info is None,
            "product_id": product_id,
            "from_seq": from_seq,
            "checked": checked,
            "tip_seq": tip["seq"] if tip else 0,
            "tip_digest": tip["digest"] if tip else None,
            "break": break_info,
        }


def _row_to_fields(r: sqlite3.Row) -> dict[str, Any]:
    import json
    return {
        "product_id": r["product_id"],
        "seq": r["seq"],
        "event_id": r["event_id"],
        "event_type": r["event_type"],
        "object_type": r["object_type"],
        "object_id": r["object_id"],
        "actor": r["actor"],
        "occurred_at": r["occurred_at"],
        "data_version": r["data_version"],
        "revision": r["revision"],
        "run_id": r["run_id"],
        "credential_id": r["credential_id"],
        "exemption_id": r["exemption_id"],
        "rule_id": r["rule_id"],
        "detail": json.loads(r["detail_json"]),
    }


def event_out(r: sqlite3.Row) -> dict[str, Any]:
    """审计事件对外序列化（detail 反序列化，摘要链原样给出）。"""
    import json
    return {
        "product_id": r["product_id"],
        "seq": r["seq"],
        "event_id": r["event_id"],
        "event_type": r["event_type"],
        "object_type": r["object_type"],
        "object_id": r["object_id"],
        "actor": r["actor"],
        "occurred_at": r["occurred_at"],
        "data_version": r["data_version"],
        "revision": r["revision"],
        "run_id": r["run_id"],
        "credential_id": r["credential_id"],
        "exemption_id": r["exemption_id"],
        "rule_id": r["rule_id"],
        "detail": json.loads(r["detail_json"]),
        "prev_digest": r["prev_digest"],
        "digest": r["digest"],
    }
