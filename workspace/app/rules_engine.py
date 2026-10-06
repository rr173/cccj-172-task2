"""规则定义校验、指纹计算与快照执行器。

执行器只接受**已发布快照**（data_version 指向的不可变行集），逐条输出
失败样本定位 (table_name, row_pk) 与规则版本指纹，保证“记录每条失败的
样本定位与规则版本”。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any

# kind -> 必需配置键
_REQUIRED: dict[str, tuple[str, ...]] = {
    "not_null": ("table", "column"),
    "unique": ("table", "columns"),
    "value_range": ("table", "column"),
    "cross_field": ("table", "left", "op", "right"),
    "cross_table": ("left_table", "left_columns", "right_table", "right_columns"),
}

_OPS = {"lt", "le", "gt", "ge", "eq", "ne"}


def fingerprint(kind: str, config: dict[str, Any]) -> str:
    payload = json.dumps(
        {"kind": kind, "config": config},
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sample_fingerprint(table_name: str, row_pk: str) -> str:
    """精确样本摘要：样本身份 = 表 + 主键值（行内容随发布快照固定）。"""
    return hashlib.sha256(
        f"{table_name} {row_pk}".encode("utf-8")
    ).hexdigest()


@dataclass
class TableSchema:
    name: str
    pk_column: str
    columns: dict[str, str]  # name -> type
    nullable: set[str]


def load_schemas(conn: sqlite3.Connection, product_id: str) -> dict[str, TableSchema]:
    rows = conn.execute(
        "SELECT table_name, pk_column, columns_json FROM tables_def WHERE product_id=?",
        (product_id,),
    ).fetchall()
    out: dict[str, TableSchema] = {}
    for r in rows:
        cols = json.loads(r["columns_json"])
        out[r["table_name"]] = TableSchema(
            name=r["table_name"],
            pk_column=r["pk_column"],
            columns={c["name"]: c["type"] for c in cols},
            nullable={c["name"] for c in cols if c["nullable"]},
        )
    return out


def validate_definition(kind: str, config: dict[str, Any],
                        schemas: dict[str, TableSchema]) -> None:
    """结构性校验；不通过抛 ValueError(中文说明)。"""
    for key in _REQUIRED[kind]:
        if key not in config:
            raise ValueError(f"规则配置缺少字段: {key}")

    def col_exists(table: str, column: str, what: str = "") -> None:
        if table not in schemas:
            raise ValueError(f"引用的数据表不存在: {table}{(' (' + what + ')') if what else ''}")
        if column not in schemas[table].columns:
            raise ValueError(f"表 {table} 上不存在字段: {column}{(' (' + what + ')') if what else ''}")

    if kind == "not_null":
        col_exists(config["table"], config["column"])

    elif kind == "unique":
        cols = config["columns"]
        if not isinstance(cols, list) or not cols or not all(isinstance(c, str) for c in cols):
            raise ValueError("unique 规则的 columns 必须是非空字符串数组")
        for c in cols:
            col_exists(config["table"], c)

    elif kind == "value_range":
        col_exists(config["table"], config["column"])
        lo, hi = config.get("min"), config.get("max")
        if lo is None and hi is None:
            raise ValueError("value_range 规则必须至少给出 min 或 max")
        for name, v in (("min", lo), ("max", hi)):
            if isinstance(v, bool) or (v is not None and not isinstance(v, (int, float))):
                raise ValueError(f"value_range 的 {name} 必须是数值")
        if lo is not None and hi is not None and lo > hi:
            raise ValueError("value_range 的 min 不能大于 max")

    elif kind == "cross_field":
        t = config["table"]
        col_exists(t, config["left"], "left")
        col_exists(t, config["right"], "right")
        if config["op"] not in _OPS:
            raise ValueError(f"cross_field 的 op 必须是 {sorted(_OPS)} 之一")

    elif kind == "cross_table":
        lt, rt = config["left_table"], config["right_table"]
        lc, rc = config["left_columns"], config["right_columns"]
        if not (isinstance(lc, list) and isinstance(rc, list) and lc and rc):
            raise ValueError("cross_table 的列数组必须非空")
        if len(lc) != len(rc):
            raise ValueError("cross_table 左右列数必须一致")
        for c in lc:
            col_exists(lt, c, "left_columns")
        for c in rc:
            col_exists(rt, c, "right_columns")


def _rows(conn: sqlite3.Connection, product_id: str, data_version: int,
          table: str) -> list[tuple[str, dict[str, Any]]]:
    rs = conn.execute(
        "SELECT row_pk, data_json FROM snapshot_rows "
        "WHERE product_id=? AND data_version=? AND table_name=? ORDER BY row_pk",
        (product_id, data_version, table),
    ).fetchall()
    return [(r["row_pk"], json.loads(r["data_json"])) for r in rs]


def _cmp(a: Any, op: str, b: Any) -> bool:
    try:
        return {
            "lt": lambda: a < b, "le": lambda: a <= b,
            "gt": lambda: a > b, "ge": lambda: a >= b,
            "eq": lambda: a == b, "ne": lambda: a != b,
        }[op]()
    except TypeError:
        return False


@dataclass
class Failure:
    rule_id: str
    rule_version: int
    rule_fingerprint: str
    table_name: str
    row_pk: str
    detail: dict[str, Any]

    @property
    def sample_fingerprint(self) -> str:
        return sample_fingerprint(self.table_name, self.row_pk)


def execute(conn: sqlite3.Connection, product_id: str, data_version: int,
            rule_id: str, rule_version: int, kind: str,
            config: dict[str, Any]) -> list[Failure]:
    """在单个发布快照上执行一条规则，返回失败样本（定位 + 版本 + 指纹）。"""
    fp = fingerprint(kind, config)
    out: list[Failure] = []

    def add(table: str, pk: str, **detail: Any) -> None:
        out.append(Failure(rule_id, rule_version, fp, table, str(pk), detail))

    if kind == "not_null":
        t, col = config["table"], config["column"]
        for pk, row in _rows(conn, product_id, data_version, t):
            if row.get(col) is None:
                add(t, pk, reason="null_value", column=col)

    elif kind == "unique":
        t, cols = config["table"], config["columns"]
        seen: dict[tuple, str] = {}
        for pk, row in _rows(conn, product_id, data_version, t):
            key = tuple(json.dumps(row.get(c), sort_keys=True) for c in cols)
            if any(v == "null" for v in key):
                continue  # NULL 不参与唯一约束
            if key in seen:
                add(t, pk, reason="duplicate", columns=cols, key=list(key),
                    first_row_pk=seen[key])
            else:
                seen[key] = pk

    elif kind == "value_range":
        t, col, lo, hi = config["table"], config["column"], config.get("min"), config.get("max")
        for pk, row in _rows(conn, product_id, data_version, t):
            v = row.get(col)
            if v is None or isinstance(v, bool) or not isinstance(v, (int, float)):
                continue
            if (lo is not None and v < lo) or (hi is not None and v > hi):
                add(t, pk, reason="out_of_range", column=col, value=v, min=lo, max=hi)

    elif kind == "cross_field":
        t = config["table"]
        l, op, r = config["left"], config["op"], config["right"]
        for pk, row in _rows(conn, product_id, data_version, t):
            a, b = row.get(l), row.get(r)
            if a is None or b is None:
                continue
            if not _cmp(a, op, b):
                add(t, pk, reason="comparison_failed",
                    left=l, left_value=a, op=op, right=r, right_value=b)

    elif kind == "cross_table":
        lt, rt = config["left_table"], config["right_table"]
        lc, rc = config["left_columns"], config["right_columns"]
        index = {
            tuple(json.dumps(row.get(c), sort_keys=True) for c in rc): pk
            for pk, row in _rows(conn, product_id, data_version, rt)
        }
        for pk, row in _rows(conn, product_id, data_version, lt):
            key = tuple(json.dumps(row.get(c), sort_keys=True) for c in lc)
            if any(v == "null" for v in key):
                continue
            if key not in index:
                add(lt, pk, reason="orphan_reference",
                    right_table=rt, left_columns=lc, right_columns=rc, key=list(key))

    return out
