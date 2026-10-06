"""SQLite 持久化层。

并发模型（数据修复 / 规则回放 / 发布冻结 / 异常豁免 四类写操作）：

* 数据库以 WAL 打开，进程内通过一把全局 ``RLock`` 串行化所有写事务；
* 写事务一律 ``BEGIN IMMEDIATE``，跨多表的状态迁移在同一事务内完成，
  杜绝“豁免写入后发布读取到旧状态”之类的交错；
* 读事务为 ``BEGIN DEFERRED``：SQLite 单连接内一个读事务持有同一快照，
  配合不可变的 run_id，分页读取永远落在同一个固定结果快照上。
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    product_id TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 表结构在产品创建时固定，对应“固定快照发布字段”
CREATE TABLE IF NOT EXISTS tables_def (
    product_id  TEXT NOT NULL,
    table_name  TEXT NOT NULL,
    pk_column   TEXT NOT NULL,
    columns_json TEXT NOT NULL,  -- [{"name","type","nullable"}]
    ordinal     INTEGER NOT NULL,
    PRIMARY KEY (product_id, table_name)
);

CREATE TABLE IF NOT EXISTS product_versions (
    product_id         TEXT NOT NULL,
    data_version       INTEGER NOT NULL,
    schema_fingerprint TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    PRIMARY KEY (product_id, data_version)
);

CREATE TABLE IF NOT EXISTS staging_rows (
    product_id TEXT NOT NULL,
    table_name TEXT NOT NULL,
    row_pk     TEXT NOT NULL,
    data_json  TEXT NOT NULL,
    PRIMARY KEY (product_id, table_name, row_pk)
);

CREATE TABLE IF NOT EXISTS snapshot_rows (
    product_id   TEXT NOT NULL,
    data_version INTEGER NOT NULL,
    table_name   TEXT NOT NULL,
    row_pk       TEXT NOT NULL,
    data_json    TEXT NOT NULL,
    PRIMARY KEY (product_id, data_version, table_name, row_pk)
);

CREATE TABLE IF NOT EXISTS repair_events (
    event_id     TEXT PRIMARY KEY,
    product_id   TEXT NOT NULL,
    base_version INTEGER NOT NULL,
    actor        TEXT NOT NULL,
    note         TEXT NOT NULL,
    upserts      INTEGER NOT NULL,
    deletes      INTEGER NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    rule_id        TEXT PRIMARY KEY,
    product_id     TEXT NOT NULL,
    name           TEXT NOT NULL,
    active_version INTEGER NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_versions (
    rule_id      TEXT NOT NULL,
    version      INTEGER NOT NULL,
    kind         TEXT NOT NULL,
    config_json  TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (rule_id, version)
);

CREATE TABLE IF NOT EXISTS rule_runs (
    run_id             TEXT PRIMARY KEY,
    product_id         TEXT NOT NULL,
    data_version       INTEGER NOT NULL,
    trigger            TEXT NOT NULL,  -- publish | replay
    ruleset_fingerprint TEXT NOT NULL,
    ruleset_json       TEXT NOT NULL,  -- 执行时刻规则集成员的完整不可变副本
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS run_failures (
    run_id           TEXT NOT NULL,
    ordinal          INTEGER NOT NULL,
    rule_id          TEXT NOT NULL,
    rule_version     INTEGER NOT NULL,
    rule_fingerprint TEXT NOT NULL,
    table_name       TEXT NOT NULL,
    row_pk           TEXT NOT NULL,
    detail_json      TEXT NOT NULL,
    sample_fingerprint TEXT NOT NULL,
    PRIMARY KEY (run_id, ordinal)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_failures_locator
    ON run_failures(run_id, rule_id, rule_version, table_name, row_pk);
CREATE INDEX IF NOT EXISTS ix_failures_lookup
    ON run_failures(run_id, sample_fingerprint, rule_fingerprint);

CREATE TABLE IF NOT EXISTS adjudications (
    product_id   TEXT NOT NULL,
    data_version INTEGER NOT NULL,
    revision     INTEGER NOT NULL,
    run_id       TEXT NOT NULL UNIQUE,
    status       TEXT NOT NULL,  -- open | frozen
    published_at TEXT NOT NULL,
    frozen_at    TEXT,
    ruleset_fingerprint TEXT NOT NULL,
    failure_count INTEGER NOT NULL,
    -- open 修订版：计数随豁免实时计算（NULL）；冻结时物化为不可变凭据事实
    suppressed_count INTEGER,
    effective_count INTEGER,
    PRIMARY KEY (product_id, data_version, revision)
);

CREATE TABLE IF NOT EXISTS exemptions (
    exemption_id       TEXT PRIMARY KEY,
    product_id         TEXT NOT NULL,
    data_version       INTEGER NOT NULL,
    rule_id            TEXT NOT NULL,
    rule_version       INTEGER NOT NULL,
    rule_fingerprint   TEXT NOT NULL,
    sample_fingerprint TEXT NOT NULL,
    table_name         TEXT NOT NULL,
    row_pk             TEXT NOT NULL,
    reason             TEXT NOT NULL,
    actor              TEXT NOT NULL,
    status             TEXT NOT NULL,  -- active | revoked
    expires_at         TEXT,
    created_at         TEXT NOT NULL,
    revoked_at         TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_exemption
    ON exemptions(product_id, data_version, rule_fingerprint, sample_fingerprint)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS ix_exemption_lookup
    ON exemptions(product_id, data_version, status, rule_fingerprint, sample_fingerprint);

CREATE TABLE IF NOT EXISTS credentials (
    cred_id      TEXT PRIMARY KEY,
    product_id   TEXT NOT NULL,
    data_version INTEGER NOT NULL,
    revision     INTEGER NOT NULL,
    body_json    TEXT NOT NULL,
    signature    TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    UNIQUE (product_id, data_version, revision)
);

-- ---------------------------------------------------------------------
-- 合规复核裁决审计账本：每产品一条独立哈希链（seq 从 1 单调递增）。
-- 只追加：UPDATE / DELETE 由触发器在引擎层拒绝；链尾摘要按
--   digest = SHA256(canonical({prev_digest, payload}))
-- 逐条链接，任何字段篡改都会在验真接口暴露为明确断点。
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
    product_id    TEXT NOT NULL,
    seq           INTEGER NOT NULL,
    event_id      TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    object_type   TEXT NOT NULL,
    object_id     TEXT,
    actor         TEXT NOT NULL,
    occurred_at   TEXT NOT NULL,
    data_version  INTEGER,
    revision      INTEGER,
    run_id        TEXT,
    credential_id TEXT,
    exemption_id  TEXT,
    rule_id       TEXT,
    detail_json   TEXT NOT NULL,
    prev_digest   TEXT NOT NULL,
    digest        TEXT NOT NULL,
    PRIMARY KEY (product_id, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_event_id ON audit_events(event_id);
CREATE INDEX IF NOT EXISTS ix_audit_product_time
    ON audit_events(product_id, occurred_at, seq);

CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only: DELETE is forbidden');
END;
"""


class Store:
    def __init__(self, path: str = ":memory:"):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            path,
            isolation_level=None,
            check_same_thread=False,
            timeout=30.0,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._lock = threading.RLock()
        self._conn.executescript(SCHEMA)

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    @contextmanager
    def tx(self, write: bool = False) -> Iterator[sqlite3.Connection]:
        """进入事务。write=True 时立即获取 RESERVED 锁。"""
        with self._lock:
            c = self._conn
            c.execute("BEGIN IMMEDIATE" if write else "BEGIN DEFERRED")
            try:
                yield c
            except Exception:
                c.execute("ROLLBACK")
                raise
            else:
                c.execute("COMMIT" if write else "COMMIT")

    # ---- 便捷方法（均在调用方事务内使用） ---------------------------------

    @staticmethod
    def qone(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        return conn.execute(sql, params).fetchone()

    @staticmethod
    def qall(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return list(conn.execute(sql, params).fetchall())

    @staticmethod
    def dumps(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
