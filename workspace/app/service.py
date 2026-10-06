"""领域服务层：数据修复、发布冻结、规则回放、异常豁免的全部裁决语义。

关键不变量：
1. 发布快照不可变：snapshot_rows 一旦写入永不更新；数据修复只作用于暂存区。
2. 规则回放只能生成新的 revision（open），任何历史 revision 及其结论不可改写。
3. 冻结把“当时”的豁免集合与计数物化进凭据正文并签名；事后豁免变化
   既改不了冻结结论，也改不了凭据。
4. 豁免严格绑定 (规则指纹, 精确样本指纹)；规则升级 → 指纹变化 → 旧豁免不匹配。
5. 所有写事务 BEGIN IMMEDIATE 并由进程锁串行化，四类操作并发安全。
"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

from . import audit, rules_engine, security
from .audit import AuditLedger
from .models import (
    AdjudicationOut,
    AuditChainStatus,
    AuditEventOut,
    AuditPage,
    CreateProduct,
    CreateRule,
    ExemptionOut,
    FailureOut,
    FailurePage,
    RepairOut,
    ReplayRequest,
    RuleOut,
    RuleVersionOut,
    TableDef,
)
from .storage import Store


class DomainError(Exception):
    def __init__(self, status_code: int, error: str, detail: Any = None):
        super().__init__(error)
        self.status_code = status_code
        self.error = error
        self.detail = detail


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(s: str | bytes) -> bytes:
    if isinstance(s, bytes):
        s = s.decode("ascii")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_TYPE_CHECKS: dict[str, Callable[[Any], bool]] = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
}


class Service:
    def __init__(self, store: Store, clock: Callable[[], datetime] = utcnow):
        self.store = store
        self.clock = clock

    # =====================================================================
    # 数据产品
    # =====================================================================

    def create_product(self, req: CreateProduct) -> dict:
        names = [t.name for t in req.tables]
        if len(set(names)) != len(names):
            raise DomainError(422, "duplicate_table", "数据表名不可重复")
        for t in req.tables:
            col_names = [c.name for c in t.columns]
            if len(set(col_names)) != len(col_names):
                raise DomainError(422, "duplicate_column", f"表 {t.name} 字段名重复")
            if t.pk_column not in col_names:
                raise DomainError(422, "pk_column_missing",
                                  f"表 {t.name} 的主键字段 {t.pk_column} 不在列定义中")
        pid = new_id("prd")
        now = iso(self.clock())
        with self.store.tx(write=True) as conn:
            conn.execute(
                "INSERT INTO products(product_id,name,created_at) VALUES(?,?,?)",
                (pid, req.name, now))
            for i, t in enumerate(sorted(req.tables, key=lambda x: x.name)):
                cols = [c.model_dump() for c in t.columns]
                conn.execute(
                    "INSERT INTO tables_def(product_id,table_name,pk_column,columns_json,ordinal)"
                    " VALUES(?,?,?,?,?)",
                    (pid, t.name, t.pk_column, Store.dumps(cols), i))
            AuditLedger.append(
                conn, product_id=pid, event_type="product_created",
                object_type="product", object_id=pid, actor="system",
                occurred_at=now,
                detail={"name": req.name,
                        "tables": [t.name for t in sorted(req.tables, key=lambda x: x.name)]})
        return self.get_product(pid)

    def list_products(self) -> list[dict]:
        with self.store.tx() as conn:
            rows = self.store.qall(conn, "SELECT * FROM products ORDER BY created_at")
            return [dict(r) for r in rows]

    def _require_product(self, conn: sqlite3.Connection, product_id: str) -> sqlite3.Row:
        row = self.store.qone(conn, "SELECT * FROM products WHERE product_id=?", (product_id,))
        if row is None:
            raise DomainError(404, "product_not_found", product_id)
        return row

    def get_product(self, product_id: str) -> dict:
        with self.store.tx() as conn:
            p = self._require_product(conn, product_id)
            trows = self.store.qall(
                conn,
                "SELECT table_name,pk_column,columns_json FROM tables_def "
                "WHERE product_id=? ORDER BY ordinal",
                (product_id,))
        tables = [
            TableDef(name=r["table_name"], pk_column=r["pk_column"],
                     columns=json.loads(r["columns_json"]))
            for r in trows
        ]
        return {"product_id": p["product_id"], "name": p["name"],
                "created_at": p["created_at"], "tables": tables}

    def list_versions(self, product_id: str) -> list[dict]:
        with self.store.tx() as conn:
            self._require_product(conn, product_id)
            rows = self.store.qall(
                conn,
                "SELECT product_id,data_version,schema_fingerprint,created_at "
                "FROM product_versions WHERE product_id=? ORDER BY data_version DESC",
                (product_id,))
        return [dict(r) for r in rows]

    def _latest_version(self, conn: sqlite3.Connection, product_id: str) -> int | None:
        r = self.store.qone(
            conn,
            "SELECT MAX(data_version) AS v FROM product_versions WHERE product_id=?",
            (product_id,))
        return r["v"] if r and r["v"] is not None else None

    # ---------- 数据修复（只写暂存区，永不触碰发布快照） -------------------

    def repair(self, product_id: str, actor: str, note: str,
               upserts: dict[str, list[dict]], deletes: dict[str, list[str]]) -> RepairOut:
        with self.store.tx(write=True) as conn:
            self._require_product(conn, product_id)
            schemas = rules_engine.load_schemas(conn, product_id)
            base = self._latest_version(conn, product_id) or 0
            n_up = n_del = 0

            for table, rows in upserts.items():
                if table not in schemas:
                    raise DomainError(422, "unknown_table", table)
                sch = schemas[table]
                for payload in rows:
                    if sch.pk_column not in payload or payload[sch.pk_column] is None:
                        raise DomainError(422, "pk_missing",
                                          f"表 {table} 的修复行必须提供主键 {sch.pk_column}")
                    unknown = set(payload) - set(sch.columns)
                    if unknown:
                        raise DomainError(422, "unknown_column",
                                          f"表 {table} 含未知字段: {sorted(unknown)}")
                    for col, val in payload.items():
                        if val is not None and not _TYPE_CHECKS[sch.columns[col]](val):
                            raise DomainError(
                                422, "type_mismatch",
                                f"表 {table}.{col} 期望 {sch.columns[col]}，收到 {type(val).__name__}")
                    pk = str(payload[sch.pk_column])
                    cur = self.store.qone(
                        conn,
                        "SELECT data_json FROM staging_rows "
                        "WHERE product_id=? AND table_name=? AND row_pk=?",
                        (product_id, table, pk))
                    merged = json.loads(cur["data_json"]) if cur else {}
                    merged.update(payload)
                    merged[sch.pk_column] = payload[sch.pk_column]
                    for col, typ in sch.columns.items():
                        if col not in sch.nullable and merged.get(col) is None:
                            raise DomainError(
                                422, "not_null_violation_in_repair",
                                f"表 {table}.{col} 不可为空（行主键 {pk}）")
                    conn.execute(
                        "INSERT INTO staging_rows(product_id,table_name,row_pk,data_json)"
                        " VALUES(?,?,?,?)"
                        " ON CONFLICT(product_id,table_name,row_pk) DO UPDATE SET data_json=excluded.data_json",
                        (product_id, table, pk, Store.dumps(merged)))
                    n_up += 1

            for table, keys in deletes.items():
                if table not in schemas:
                    raise DomainError(422, "unknown_table", table)
                for key in keys:
                    cur = conn.execute(
                        "DELETE FROM staging_rows WHERE product_id=? AND table_name=? AND row_pk=?",
                        (product_id, table, str(key)))
                    n_del += cur.rowcount

            event_id = new_id("evt")
            created_at = iso(self.clock())
            conn.execute(
                "INSERT INTO repair_events(event_id,product_id,base_version,actor,note,"
                "upserts,deletes,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (event_id, product_id, base, actor, note, n_up, n_del, created_at))
            AuditLedger.append(
                conn, product_id=product_id, event_type="data_repaired",
                object_type="repair_event", object_id=event_id, actor=actor,
                occurred_at=created_at, data_version=base,
                detail={"repair_event_id": event_id, "base_version": base,
                        "upserts": n_up, "deletes": n_del, "note": note})
        return RepairOut(event_id=event_id, base_version=base,
                         upserts=n_up, deletes=n_del, created_at=created_at)

    # ---------- 发布：暂存区 → 不可变快照 + 首版裁决 ----------------------

    def _staging_map(self, conn: sqlite3.Connection, product_id: str) -> dict[str, dict[str, str]]:
        rows = self.store.qall(
            conn,
            "SELECT table_name,row_pk,data_json FROM staging_rows WHERE product_id=?",
            (product_id,))
        out: dict[str, dict[str, str]] = {}
        for r in rows:
            out.setdefault(r["table_name"], {})[r["row_pk"]] = r["data_json"]
        return out

    def _snapshot_map(self, conn: sqlite3.Connection, product_id: str,
                      data_version: int) -> dict[str, dict[str, str]]:
        rows = self.store.qall(
            conn,
            "SELECT table_name,row_pk,data_json FROM snapshot_rows "
            "WHERE product_id=? AND data_version=?",
            (product_id, data_version))
        out: dict[str, dict[str, str]] = {}
        for r in rows:
            out.setdefault(r["table_name"], {})[r["row_pk"]] = r["data_json"]
        return out

    def _schema_fingerprint(self, conn: sqlite3.Connection, product_id: str) -> str:
        rows = self.store.qall(
            conn,
            "SELECT table_name,pk_column,columns_json FROM tables_def "
            "WHERE product_id=? ORDER BY ordinal", (product_id,))
        canon = [{"table": r["table_name"], "pk": r["pk_column"],
                  "columns": json.loads(r["columns_json"])} for r in rows]
        return hashlib.sha256(Store.dumps(canon).encode()).hexdigest()

    def _active_rules(self, conn: sqlite3.Connection, product_id: str) -> list[sqlite3.Row]:
        rows = self.store.qall(
            conn,
            "SELECT r.rule_id AS rule_id, r.active_version AS version, rv.kind AS kind,"
            " rv.config_json AS config_json, rv.fingerprint AS fingerprint "
            "FROM rules r JOIN rule_versions rv "
            "ON rv.rule_id=r.rule_id AND rv.version=r.active_version "
            "WHERE r.product_id=? ORDER BY r.rule_id", (product_id,))
        return rows

    def _ruleset_fingerprint(self, rules: Iterable[sqlite3.Row | dict]) -> str:
        items = sorted(
            ({"rule_id": r["rule_id"], "rule_version": r["version"],
              "rule_fingerprint": r["fingerprint"]} for r in rules),
            key=lambda x: x["rule_id"])
        return hashlib.sha256(Store.dumps(items).encode()).hexdigest()

    @staticmethod
    def _ruleset_archive(rules: Iterable[sqlite3.Row | dict]) -> list[dict]:
        """执行时刻规则集的不可变存档（run 与凭据据此复原零失败规则）。"""
        return sorted(({
            "rule_id": r["rule_id"],
            "rule_version": r["version"],
            "rule_fingerprint": r["fingerprint"],
            "kind": r["kind"],
            "config": json.loads(r["config_json"]),
        } for r in rules), key=lambda x: x["rule_id"])

    def _execute_ruleset(self, conn: sqlite3.Connection, product_id: str,
                         data_version: int, rules: list[sqlite3.Row | dict]
                         ) -> list[rules_engine.Failure]:
        failures: list[rules_engine.Failure] = []
        for r in sorted(rules, key=lambda x: x["rule_id"]):
            failures.extend(rules_engine.execute(
                conn, product_id, data_version,
                rule_id=r["rule_id"], rule_version=r["version"],
                kind=r["kind"], config=json.loads(r["config_json"])))
        # 规则间再按 (表, 主键) 稳定排序，序号完全确定
        failures.sort(key=lambda f: (f.table_name, f.row_pk, f.rule_id))
        return failures

    def _record_run(self, conn: sqlite3.Connection, product_id: str, data_version: int,
                    trigger: str, rules: list, failures: list) -> str:
        run_id = new_id("run")
        conn.execute(
            "INSERT INTO rule_runs(run_id,product_id,data_version,trigger,"
            "ruleset_fingerprint,ruleset_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (run_id, product_id, data_version, trigger,
             self._ruleset_fingerprint(rules),
             Store.dumps(self._ruleset_archive(rules)), iso(self.clock())))
        for i, f in enumerate(failures, start=1):
            conn.execute(
                "INSERT INTO run_failures(run_id,ordinal,rule_id,rule_version,"
                "rule_fingerprint,table_name,row_pk,detail_json,sample_fingerprint)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (run_id, i, f.rule_id, f.rule_version, f.rule_fingerprint,
                 f.table_name, f.row_pk, Store.dumps(f.detail), f.sample_fingerprint))
        return run_id

    def publish(self, product_id: str, actor: str, note: str) -> AdjudicationOut:
        with self.store.tx(write=True) as conn:
            self._require_product(conn, product_id)
            latest = self._latest_version(conn, product_id)
            staging = self._staging_map(conn, product_id)
            if latest is not None and staging == self._snapshot_map(conn, product_id, latest):
                raise DomainError(409, "no_changes_since_last_version",
                                  {"latest_version": latest})
            new_version = (latest or 0) + 1
            published_at = iso(self.clock())
            # 暂存区整体冻结为不可变快照
            for table, rows in staging.items():
                for pk, payload in rows.items():
                    conn.execute(
                        "INSERT INTO snapshot_rows(product_id,data_version,table_name,row_pk,data_json)"
                        " VALUES(?,?,?,?,?)",
                        (product_id, new_version, table, pk, payload))
            sfp = self._schema_fingerprint(conn, product_id)
            conn.execute(
                "INSERT INTO product_versions(product_id,data_version,schema_fingerprint,created_at)"
                " VALUES(?,?,?,?)",
                (product_id, new_version, sfp, published_at))
            rules = self._active_rules(conn, product_id)
            failures = self._execute_ruleset(conn, product_id, new_version, rules)
            run_id = self._record_run(conn, product_id, new_version, "publish", rules, failures)
            conn.execute(
                "INSERT INTO adjudications(product_id,data_version,revision,run_id,status,"
                "published_at,frozen_at,ruleset_fingerprint,failure_count,"
                "suppressed_count,effective_count) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (product_id, new_version, 1, run_id, "open",
                 published_at, None, self._ruleset_fingerprint(rules),
                 len(failures), None, None))
            AuditLedger.append(
                conn, product_id=product_id, event_type="adjudication_published",
                object_type="adjudication",
                object_id=f"{product_id}:v{new_version}:r1",
                actor=actor, occurred_at=published_at,
                data_version=new_version, revision=1, run_id=run_id,
                detail={"data_version": new_version, "revision": 1,
                        "trigger": "publish", "failure_count": len(failures),
                        "ruleset_fingerprint": self._ruleset_fingerprint(rules),
                        "schema_fingerprint": sfp, "note": note})
            adj = self._load_adjudication(conn, product_id, new_version, 1)
        return self._adjudication_out(adj)

    # =====================================================================
    # 规则与回放
    # =====================================================================

    def create_rule(self, req: CreateRule) -> RuleOut:
        with self.store.tx(write=True) as conn:
            self._require_product(conn, req.product_id)
            schemas = rules_engine.load_schemas(conn, req.product_id)
            try:
                rules_engine.validate_definition(req.kind, req.config, schemas)
            except ValueError as e:
                raise DomainError(422, "invalid_rule", str(e))
            rule_id = new_id("rule")
            now = iso(self.clock())
            conn.execute(
                "INSERT INTO rules(rule_id,product_id,name,active_version,created_at)"
                " VALUES(?,?,?,?,?)",
                (rule_id, req.product_id, req.name, 1, now))
            conn.execute(
                "INSERT INTO rule_versions(rule_id,version,kind,config_json,fingerprint,created_at)"
                " VALUES(?,?,?,?,?,?)",
                (rule_id, 1, req.kind, Store.dumps(req.config),
                 rules_engine.fingerprint(req.kind, req.config), now))
            AuditLedger.append(
                conn, product_id=req.product_id, event_type="rule_registered",
                object_type="rule", object_id=rule_id, actor="system",
                occurred_at=now, rule_id=rule_id,
                detail={"rule_id": rule_id, "name": req.name, "kind": req.kind,
                        "version": 1, "config": req.config,
                        "rule_fingerprint": rules_engine.fingerprint(req.kind, req.config)})
        return self.get_rule(rule_id)

    def _require_rule(self, conn: sqlite3.Connection, rule_id: str) -> sqlite3.Row:
        row = self.store.qone(conn, "SELECT * FROM rules WHERE rule_id=?", (rule_id,))
        if row is None:
            raise DomainError(404, "rule_not_found", rule_id)
        return row

    def add_rule_version(self, rule_id: str, kind: str, config: dict) -> RuleOut:
        with self.store.tx(write=True) as conn:
            rule = self._require_rule(conn, rule_id)
            schemas = rules_engine.load_schemas(conn, rule["product_id"])
            active_kind = self.store.qone(
                conn, "SELECT kind FROM rule_versions WHERE rule_id=? AND version=?",
                (rule_id, rule["active_version"]))["kind"]
            if kind != active_kind:
                raise DomainError(422, "kind_change_not_allowed",
                                  "规则升级不可改变规则类型；请创建新规则")
            try:
                rules_engine.validate_definition(kind, config, schemas)
            except ValueError as e:
                raise DomainError(422, "invalid_rule", str(e))
            fp = rules_engine.fingerprint(kind, config)
            dup = self.store.qone(
                conn, "SELECT 1 FROM rule_versions WHERE rule_id=? AND fingerprint=?",
                (rule_id, fp))
            if dup is not None:
                raise DomainError(409, "rule_version_unchanged",
                                  "新版本定义与既有版本指纹完全相同")
            version = rule["active_version"] + 1
            now = iso(self.clock())
            conn.execute(
                "INSERT INTO rule_versions(rule_id,version,kind,config_json,fingerprint,created_at)"
                " VALUES(?,?,?,?,?,?)",
                (rule_id, version, kind, Store.dumps(config), fp, now))
            conn.execute("UPDATE rules SET active_version=? WHERE rule_id=?",
                         (version, rule_id))
            AuditLedger.append(
                conn, product_id=rule["product_id"], event_type="rule_upgraded",
                object_type="rule", object_id=rule_id, actor="system",
                occurred_at=now, rule_id=rule_id,
                detail={"rule_id": rule_id, "version": version, "kind": kind,
                        "config": config, "rule_fingerprint": fp,
                        "previous_version": rule["active_version"],
                        "activated": True})
        return self.get_rule(rule_id)

    def activate_rule(self, rule_id: str, version: int) -> RuleOut:
        with self.store.tx(write=True) as conn:
            rule = self._require_rule(conn, rule_id)
            row = self.store.qone(
                conn, "SELECT 1 FROM rule_versions WHERE rule_id=? AND version=?",
                (rule_id, version))
            if row is None:
                raise DomainError(404, "rule_version_not_found",
                                  {"rule_id": rule_id, "version": version})
            fp_row = self.store.qone(
                conn, "SELECT fingerprint,kind,config_json FROM rule_versions "
                      "WHERE rule_id=? AND version=?", (rule_id, version))
            now = iso(self.clock())
            conn.execute("UPDATE rules SET active_version=? WHERE rule_id=?",
                         (version, rule_id))
            if version != rule["active_version"]:
                AuditLedger.append(
                    conn, product_id=rule["product_id"], event_type="rule_activated",
                    object_type="rule", object_id=rule_id, actor="system",
                    occurred_at=now, rule_id=rule_id,
                    detail={"rule_id": rule_id, "version": version,
                            "kind": fp_row["kind"],
                            "rule_fingerprint": fp_row["fingerprint"],
                            "previous_version": rule["active_version"]})
        return self.get_rule(rule_id)

    def list_rules(self, product_id: str) -> list[RuleOut]:
        with self.store.tx() as conn:
            self._require_product(conn, product_id)
            ids = [r["rule_id"] for r in self.store.qall(
                conn, "SELECT rule_id FROM rules WHERE product_id=? ORDER BY rule_id",
                (product_id,))]
        return [self.get_rule(rid) for rid in ids]

    def get_rule(self, rule_id: str) -> RuleOut:
        with self.store.tx() as conn:
            rule = self._require_rule(conn, rule_id)
            vrows = self.store.qall(
                conn, "SELECT * FROM rule_versions WHERE rule_id=? ORDER BY version",
                (rule_id,))
        versions = [
            RuleVersionOut(rule_id=rule_id, version=r["version"], kind=r["kind"],
                           config=json.loads(r["config_json"]), fingerprint=r["fingerprint"],
                           is_active=r["version"] == rule["active_version"],
                           created_at=r["created_at"])
            for r in vrows
        ]
        return RuleOut(rule_id=rule_id, product_id=rule["product_id"],
                       name=rule["name"], active_version=rule["active_version"],
                       versions=versions)

    def replay(self, product_id: str, req: ReplayRequest) -> AdjudicationOut:
        """规则升级对历史快照回放：只产出新的 open 修订版。"""
        with self.store.tx(write=True) as conn:
            self._require_product(conn, product_id)
            version = self._latest_version(conn, product_id)
            if version is None:
                raise DomainError(404, "no_published_version", "产品尚无发布快照")
            if req.rule_versions is None:
                rules = list(self._active_rules(conn, product_id))
            else:
                if not req.rule_versions:
                    raise DomainError(422, "empty_ruleset", "回放规则集不能为空")
                rules = []
                for rid, ver in sorted(req.rule_versions.items()):
                    rr = self.store.qone(
                        conn,
                        "SELECT r.product_id AS product_id, rv.version AS version, rv.kind AS kind,"
                        " rv.config_json AS config_json, rv.fingerprint AS fingerprint,"
                        " r.rule_id AS rule_id "
                        "FROM rules r JOIN rule_versions rv ON rv.rule_id=r.rule_id "
                        "WHERE r.rule_id=? AND rv.version=?", (rid, ver))
                    if rr is None:
                        raise DomainError(404, "rule_version_not_found",
                                          {"rule_id": rid, "version": ver})
                    if rr["product_id"] != product_id:
                        raise DomainError(422, "rule_belongs_to_other_product", rid)
                    rules.append(rr)
            rsfp = self._ruleset_fingerprint(rules)
            clash = self.store.qone(
                conn,
                "SELECT 1 FROM adjudications a JOIN rule_runs r ON r.run_id=a.run_id "
                "WHERE a.product_id=? AND a.data_version=? AND r.ruleset_fingerprint=?",
                (product_id, version, rsfp))
            if clash is not None:
                raise DomainError(409, "ruleset_already_adjudicated",
                                  "该规则集对此快照已形成裁决；回放必须包含规则变化")
            failures = self._execute_ruleset(conn, product_id, version, rules)
            run_id = self._record_run(conn, product_id, version, "replay", rules, failures)
            rev = self.store.qone(
                conn,
                "SELECT COALESCE(MAX(revision),0)+1 AS n FROM adjudications "
                "WHERE product_id=? AND data_version=?", (product_id, version))["n"]
            now = iso(self.clock())
            conn.execute(
                "INSERT INTO adjudications(product_id,data_version,revision,run_id,status,"
                "published_at,frozen_at,ruleset_fingerprint,failure_count,"
                "suppressed_count,effective_count) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (product_id, version, rev, run_id, "open",
                 now, None, rsfp, len(failures), None, None))
            AuditLedger.append(
                conn, product_id=product_id, event_type="revision_requested",
                object_type="adjudication",
                object_id=f"{product_id}:v{version}:r{rev}",
                actor=req.actor, occurred_at=now,
                data_version=version, revision=rev, run_id=run_id,
                detail={"data_version": version, "revision": rev,
                        "trigger": "replay", "failure_count": len(failures),
                        "ruleset_fingerprint": rsfp,
                        "rule_versions": {r["rule_id"]: r["version"] for r in rules}})
            adj = self._load_adjudication(conn, product_id, version, rev)
        return self._adjudication_out(adj)

    # =====================================================================
    # 裁决与冻结
    # =====================================================================

    def _load_adjudication(self, conn: sqlite3.Connection, product_id: str,
                           data_version: int, revision: int) -> sqlite3.Row:
        row = self.store.qone(
            conn,
            "SELECT a.*, r.trigger AS trigger FROM adjudications a "
            "JOIN rule_runs r ON r.run_id=a.run_id "
            "WHERE a.product_id=? AND a.data_version=? AND a.revision=?",
            (product_id, data_version, revision))
        if row is None:
            raise DomainError(404, "adjudication_not_found",
                              {"product_id": product_id, "data_version": data_version,
                               "revision": revision})
        return row

    def _live_counts(self, conn: sqlite3.Connection, run_id: str) -> tuple[int, int]:
        now = iso(self.clock())
        total = self.store.qone(
            conn, "SELECT COUNT(*) AS c FROM run_failures WHERE run_id=?", (run_id,))["c"]
        suppressed = self.store.qone(
            conn,
            "SELECT COUNT(*) AS c FROM run_failures f WHERE f.run_id=? AND EXISTS ("
            "SELECT 1 FROM exemptions e WHERE e.product_id="
            "(SELECT product_id FROM rule_runs WHERE run_id=f.run_id) "
            "AND e.data_version=(SELECT data_version FROM rule_runs WHERE run_id=f.run_id) "
            "AND e.status='active' AND e.rule_fingerprint=f.rule_fingerprint "
            "AND e.sample_fingerprint=f.sample_fingerprint "
            "AND (e.expires_at IS NULL OR e.expires_at > ?))",
            (run_id, now))["c"]
        return total, suppressed

    def _adjudication_out_conn(self, conn: sqlite3.Connection,
                               row: sqlite3.Row) -> AdjudicationOut:
        """必须在已持有的事务连接上调用（不另开事务）。"""
        if row["status"] == "frozen":
            total, suppressed = row["failure_count"], row["suppressed_count"]
        else:
            total, suppressed = self._live_counts(conn, row["run_id"])
        effective = total - suppressed
        cred = self.store.qone(
            conn, "SELECT cred_id FROM credentials WHERE product_id=? AND data_version=? AND revision=?",
            (row["product_id"], row["data_version"], row["revision"]))
        return AdjudicationOut(
            product_id=row["product_id"], data_version=row["data_version"],
            revision=row["revision"], run_id=row["run_id"], status=row["status"],
            trigger=row["trigger"], ruleset_fingerprint=row["ruleset_fingerprint"],
            failure_count=total, suppressed_count=suppressed, effective_count=effective,
            verdict="pass" if effective == 0 else "fail",
            published_at=row["published_at"], frozen_at=row["frozen_at"],
            credential_id=cred["cred_id"] if cred else None)

    def _adjudication_out(self, row: sqlite3.Row) -> AdjudicationOut:
        with self.store.tx() as conn:
            return self._adjudication_out_conn(conn, row)

    def list_adjudications(self, product_id: str,
                           data_version: int | None = None) -> list[AdjudicationOut]:
        with self.store.tx() as conn:
            self._require_product(conn, product_id)
            if data_version is None:
                data_version = self._latest_version(conn, product_id)
                if data_version is None:
                    return []
            rows = self.store.qall(
                conn,
                "SELECT a.*, r.trigger AS trigger FROM adjudications a "
                "JOIN rule_runs r ON r.run_id=a.run_id "
                "WHERE a.product_id=? AND a.data_version=? ORDER BY a.revision",
                (product_id, data_version))
        return [self._adjudication_out(r) for r in rows]

    def adjudication_by_run(self, run_id: str) -> AdjudicationOut:
        with self.store.tx() as conn:
            loc = self.store.qone(
                conn, "SELECT product_id,data_version FROM rule_runs WHERE run_id=?",
                (run_id,))
            if loc is None:
                raise DomainError(404, "run_not_found", run_id)
            row = self.store.qone(
                conn,
                "SELECT a.*, r.trigger AS trigger FROM adjudications a "
                "JOIN rule_runs r ON r.run_id=a.run_id WHERE a.run_id=?",
                (run_id,))
            return self._adjudication_out_conn(conn, row)

    def freeze(self, product_id: str, data_version: int | None = None
               ) -> tuple[AdjudicationOut, dict, str]:
        """冻结某快照最新修订版的发布判断；幂等：重复冻结返回原凭据。"""
        # 签名密钥的惰性生成发生在写事务之外，避免同连接嵌套事务
        priv_pem, _ = security.get_or_create_keypair(self.store)
        with self.store.tx(write=True) as conn:
            self._require_product(conn, product_id)
            if data_version is None:
                data_version = self._latest_version(conn, product_id)
                if data_version is None:
                    raise DomainError(404, "no_published_version", "产品尚无发布快照")
            rev_row = self.store.qone(
                conn,
                "SELECT COALESCE(MAX(revision),0) AS m FROM adjudications "
                "WHERE product_id=? AND data_version=?", (product_id, data_version))
            if rev_row["m"] == 0:
                raise DomainError(404, "adjudication_not_found",
                                  {"product_id": product_id, "data_version": data_version})
            revision = rev_row["m"]
            adj = self._load_adjudication(conn, product_id, data_version, revision)
            existing = self.store.qone(
                conn, "SELECT * FROM credentials WHERE product_id=? AND data_version=? AND revision=?",
                (product_id, data_version, revision))
            if existing is not None:
                body = json.loads(existing["body_json"])
                out = self._adjudication_out_conn(conn, adj)
                return out, body, existing["signature"]

            total, suppressed = self._live_counts(conn, adj["run_id"])
            effective = total - suppressed
            frozen_at = iso(self.clock())
            conn.execute(
                "UPDATE adjudications SET status='frozen', frozen_at=?,"
                " suppressed_count=?, effective_count=? "
                "WHERE product_id=? AND data_version=? AND revision=?",
                (frozen_at, suppressed, effective, product_id, data_version, revision))

            # 凭据中的规则清单取自 run 的不可变规则集存档（含零失败规则）
            rs_rules = json.loads(self.store.qone(
                conn, "SELECT ruleset_json FROM rule_runs WHERE run_id=?",
                (adj["run_id"],))["ruleset_json"])
            exempt_rows = self.store.qall(
                conn,
                "SELECT exemption_id,rule_fingerprint,sample_fingerprint,table_name,row_pk,"
                "expires_at,created_at FROM exemptions "
                "WHERE product_id=? AND data_version=? AND status='active' "
                "AND (expires_at IS NULL OR expires_at > ?)",
                (product_id, data_version, frozen_at))
            schema_fp = self.store.qone(
                conn, "SELECT schema_fingerprint FROM product_versions "
                "WHERE product_id=? AND data_version=?",
                (product_id, data_version))["schema_fingerprint"]
            cred_id = new_id("cred")
            body = {
                "credential_id": cred_id,
                "format_version": "1.0",
                "platform": "dq-versioned-adjudication",
                "product_id": product_id,
                "data_version": data_version,
                "revision": revision,
                "run_id": adj["run_id"],
                "status": "frozen",
                "published_at": adj["published_at"],
                "frozen_at": frozen_at,
                "schema_fingerprint": schema_fp,
                "ruleset_fingerprint": adj["ruleset_fingerprint"],
                "verdict": "pass" if effective == 0 else "fail",
                "failure_count": total,
                "suppressed_count": suppressed,
                "effective_count": effective,
                "rules": rs_rules,
                "active_exemptions": [
                    {"exemption_id": e["exemption_id"],
                     "rule_fingerprint": e["rule_fingerprint"],
                     "sample_fingerprint": e["sample_fingerprint"],
                     "table_name": e["table_name"], "row_pk": e["row_pk"],
                     "expires_at": e["expires_at"], "created_at": e["created_at"]}
                    for e in exempt_rows],
            }
            signature = security.sign_with_pem(priv_pem, body)
            conn.execute(
                "INSERT INTO credentials(cred_id,product_id,data_version,revision,"
                "body_json,signature,created_at) VALUES(?,?,?,?,?,?,?)",
                (cred_id, product_id, data_version, revision,
                 Store.dumps(body), signature, frozen_at))
            # 冻结与凭据签发是两个独立合规事件，同一事务内顺序追加；
            # 幂等再冻结走上面的既有凭据分支，不产生新事件。
            AuditLedger.append(
                conn, product_id=product_id, event_type="adjudication_frozen",
                object_type="adjudication",
                object_id=f"{product_id}:v{data_version}:r{revision}",
                actor="system", occurred_at=frozen_at,
                data_version=data_version, revision=revision, run_id=adj["run_id"],
                detail={"data_version": data_version, "revision": revision,
                        "verdict": body["verdict"], "failure_count": total,
                        "suppressed_count": suppressed,
                        "effective_count": effective})
            AuditLedger.append(
                conn, product_id=product_id, event_type="credential_issued",
                object_type="credential", object_id=cred_id,
                actor="system", occurred_at=frozen_at,
                data_version=data_version, revision=revision, run_id=adj["run_id"],
                credential_id=cred_id,
                detail={"credential_id": cred_id,
                        "ruleset_fingerprint": adj["ruleset_fingerprint"],
                        "verdict": body["verdict"], "algorithm": "Ed25519"})
            adj = self._load_adjudication(conn, product_id, data_version, revision)
            out = self._adjudication_out_conn(conn, adj)
            return out, body, signature

    # =====================================================================
    # 失败样本分页（固定 run_id 快照）
    # =====================================================================

    def failures_page(self, run_id: str, cursor: str | None, page_size: int) -> FailurePage:
        if page_size < 1 or page_size > 200:
            raise DomainError(422, "invalid_page_size", "page_size 须在 1..200")
        last_ord = 0
        if cursor:
            try:
                token = json.loads(_b64d(cursor.encode()))
            except Exception:
                raise DomainError(400, "invalid_cursor", "游标无法解析")
            if token.get("run_id") != run_id:
                raise DomainError(409, "cursor_snapshot_mismatch",
                                  "游标属于另一个结果快照，不可跨 run 分页")
            last_ord = int(token.get("ordinal", 0))

        with self.store.tx() as conn:
            run = self.store.qone(conn, "SELECT * FROM rule_runs WHERE run_id=?", (run_id,))
            if run is None:
                raise DomainError(404, "run_not_found", run_id)
            adj = self.store.qone(
                conn, "SELECT * FROM adjudications WHERE run_id=?", (run_id,))
            frozen_keys: set[tuple[str, str]] | None = None
            if adj["status"] == "frozen":
                cred = self.store.qone(
                    conn, "SELECT body_json FROM credentials WHERE product_id=? AND data_version=? AND revision=?",
                    (adj["product_id"], adj["data_version"], adj["revision"]))
                body = json.loads(cred["body_json"])
                frozen_keys = {(e["rule_fingerprint"], e["sample_fingerprint"])
                               for e in body["active_exemptions"]}
            now = iso(self.clock())
            rows = self.store.qall(
                conn,
                "SELECT * FROM run_failures WHERE run_id=? AND ordinal>? ORDER BY ordinal LIMIT ?",
                (run_id, last_ord, page_size + 1))
            items: list[FailureOut] = []
            next_cursor = None
            page = rows[:page_size]
            if len(rows) > page_size:
                next_cursor = _b64e(Store.dumps(
                    {"run_id": run_id, "ordinal": page[-1]["ordinal"]}).encode())
            for r in page:
                supp = None
                if frozen_keys is not None:
                    is_supp = (r["rule_fingerprint"], r["sample_fingerprint"]) in frozen_keys
                    if is_supp:
                        e = self.store.qone(
                            conn,
                            "SELECT exemption_id,reason,actor,expires_at FROM exemptions "
                            "WHERE product_id=? AND data_version=? AND status='active' "
                            "AND rule_fingerprint=? AND sample_fingerprint=?",
                            (run["product_id"], run["data_version"],
                             r["rule_fingerprint"], r["sample_fingerprint"]))
                        supp = dict(e) if e else {"frozen": True}
                else:
                    e = self.store.qone(
                        conn,
                        "SELECT exemption_id,reason,actor,expires_at FROM exemptions "
                        "WHERE product_id=? AND data_version=? AND status='active' "
                        "AND rule_fingerprint=? AND sample_fingerprint=? "
                        "AND (expires_at IS NULL OR expires_at > ?)",
                        (run["product_id"], run["data_version"],
                         r["rule_fingerprint"], r["sample_fingerprint"], now))
                    is_supp = e is not None
                    if e is not None:
                        supp = dict(e)
                items.append(FailureOut(
                    ordinal=r["ordinal"], rule_id=r["rule_id"],
                    rule_version=r["rule_version"], rule_fingerprint=r["rule_fingerprint"],
                    table_name=r["table_name"], row_pk=r["row_pk"],
                    sample_fingerprint=r["sample_fingerprint"],
                    detail=json.loads(r["detail_json"]),
                    suppressed=is_supp, suppression=supp))
        return FailurePage(
            run_id=run_id, product_id=run["product_id"],
            data_version=run["data_version"], revision=adj["revision"],
            adjudication_status=adj["status"], page_size=page_size,
            next_cursor=next_cursor, items=items)

    # =====================================================================
    # 异常豁免工作台
    # =====================================================================

    def grant_exemption(self, run_id: str, ordinal: int, actor: str,
                        reason: str, ttl_seconds: int | None) -> ExemptionOut:
        with self.store.tx(write=True) as conn:
            run = self.store.qone(conn, "SELECT * FROM rule_runs WHERE run_id=?", (run_id,))
            if run is None:
                raise DomainError(404, "run_not_found", run_id)
            f = self.store.qone(
                conn, "SELECT * FROM run_failures WHERE run_id=? AND ordinal=?",
                (run_id, ordinal))
            if f is None:
                raise DomainError(404, "failure_not_found",
                                  {"run_id": run_id, "ordinal": ordinal})
            adj = self.store.qone(
                conn, "SELECT * FROM adjudications WHERE run_id=?", (run_id,))
            if adj["status"] == "frozen":
                raise DomainError(409, "adjudication_frozen",
                                  "裁决已冻结：豁免只能作用于开放修订版，不能追加到冻结判断")
            dup = self.store.qone(
                conn,
                "SELECT exemption_id FROM exemptions WHERE product_id=? AND data_version=? "
                "AND rule_fingerprint=? AND sample_fingerprint=? AND status='active'",
                (run["product_id"], run["data_version"],
                 f["rule_fingerprint"], f["sample_fingerprint"]))
            if dup is not None:
                raise DomainError(409, "exemption_exists",
                                  {"exemption_id": dup["exemption_id"]})
            now = self.clock()
            created_at = iso(now)
            expires = iso(now + timedelta(seconds=ttl_seconds)) if ttl_seconds else None
            eid = new_id("exmp")
            conn.execute(
                "INSERT INTO exemptions(exemption_id,product_id,data_version,rule_id,"
                "rule_version,rule_fingerprint,sample_fingerprint,table_name,row_pk,"
                "reason,actor,status,expires_at,created_at,revoked_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (eid, run["product_id"], run["data_version"], f["rule_id"],
                 f["rule_version"], f["rule_fingerprint"], f["sample_fingerprint"],
                 f["table_name"], f["row_pk"], reason, actor, "active",
                 expires, created_at, None))
            AuditLedger.append(
                conn, product_id=run["product_id"], event_type="exemption_granted",
                object_type="exemption", object_id=eid, actor=actor,
                occurred_at=created_at,
                data_version=run["data_version"], run_id=run_id, exemption_id=eid,
                rule_id=f["rule_id"],
                detail={"exemption_id": eid, "run_id": run_id,
                        "data_version": run["data_version"],
                        "rule_id": f["rule_id"], "rule_version": f["rule_version"],
                        "rule_fingerprint": f["rule_fingerprint"],
                        "sample_fingerprint": f["sample_fingerprint"],
                        "table_name": f["table_name"], "row_pk": f["row_pk"],
                        "reason": reason, "expires_at": expires})
            row = self.store.qone(
                conn, "SELECT * FROM exemptions WHERE exemption_id=?", (eid,))
        return self._exemption_out(row)

    def revoke_exemption(self, exemption_id: str, actor: str, reason: str) -> ExemptionOut:
        with self.store.tx(write=True) as conn:
            row = self.store.qone(
                conn, "SELECT * FROM exemptions WHERE exemption_id=?", (exemption_id,))
            if row is None:
                raise DomainError(404, "exemption_not_found", exemption_id)
            if row["status"] == "revoked":
                raise DomainError(409, "exemption_already_revoked", exemption_id)
            revoked_at = iso(self.clock())
            conn.execute(
                "UPDATE exemptions SET status='revoked', revoked_at=? WHERE exemption_id=?",
                (revoked_at, exemption_id))
            AuditLedger.append(
                conn, product_id=row["product_id"], event_type="exemption_revoked",
                object_type="exemption", object_id=exemption_id, actor=actor,
                occurred_at=revoked_at,
                data_version=row["data_version"], exemption_id=exemption_id,
                rule_id=row["rule_id"],
                detail={"exemption_id": exemption_id,
                        "data_version": row["data_version"],
                        "rule_id": row["rule_id"], "rule_version": row["rule_version"],
                        "rule_fingerprint": row["rule_fingerprint"],
                        "sample_fingerprint": row["sample_fingerprint"],
                        "table_name": row["table_name"], "row_pk": row["row_pk"],
                        "reason": reason})
            row = self.store.qone(
                conn, "SELECT * FROM exemptions WHERE exemption_id=?", (exemption_id,))
        return self._exemption_out(row)

    def _exemption_out(self, row: sqlite3.Row) -> ExemptionOut:
        return ExemptionOut(
            exemption_id=row["exemption_id"], product_id=row["product_id"],
            data_version=row["data_version"], rule_id=row["rule_id"],
            rule_version=row["rule_version"], rule_fingerprint=row["rule_fingerprint"],
            sample_fingerprint=row["sample_fingerprint"], table_name=row["table_name"],
            row_pk=row["row_pk"], reason=row["reason"], actor=row["actor"],
            status=row["status"], expires_at=row["expires_at"],
            created_at=row["created_at"], revoked_at=row["revoked_at"])

    def list_exemptions(self, product_id: str, data_version: int | None,
                        status: str | None, page_size: int,
                        cursor: str | None) -> tuple[list[ExemptionOut], str | None]:
        if status not in (None, "active", "revoked"):
            raise DomainError(422, "invalid_status", status)
        where = ["product_id=?"]
        params: list[Any] = [product_id]
        if data_version is not None:
            where.append("data_version=?")
            params.append(data_version)
        if status:
            where.append("status=?")
            params.append(status)
        if cursor:
            where.append("exemption_id > ?")
            params.append(cursor)
        params.append(page_size + 1)
        with self.store.tx() as conn:
            self._require_product(conn, product_id)
            rows = self.store.qall(
                conn,
                f"SELECT * FROM exemptions WHERE {' AND '.join(where)} "
                "ORDER BY exemption_id LIMIT ?", params)
        page = rows[:page_size]
        nxt = page[-1]["exemption_id"] if len(rows) > page_size else None
        return [self._exemption_out(r) for r in page], nxt

    # =====================================================================
    # 凭据
    # =====================================================================

    def get_credential(self, product_id: str, data_version: int,
                       revision: int) -> tuple[dict, str]:
        with self.store.tx() as conn:
            self._require_product(conn, product_id)
            row = self.store.qone(
                conn, "SELECT body_json,signature FROM credentials "
                "WHERE product_id=? AND data_version=? AND revision=?",
                (product_id, data_version, revision))
            if row is None:
                adj = self.store.qone(
                    conn, "SELECT status FROM adjudications "
                    "WHERE product_id=? AND data_version=? AND revision=?",
                    (product_id, data_version, revision))
                if adj is None:
                    raise DomainError(404, "adjudication_not_found")
                raise DomainError(409, "not_frozen",
                                  "该修订版尚未冻结；冻结后方可下载质量凭据")
        return json.loads(row["body_json"]), row["signature"]

    def resolve_revision(self, product_id: str, data_version: int,
                         revision: int | str) -> int:
        if isinstance(revision, int):
            return revision
        if revision != "latest":
            raise DomainError(400, "invalid_revision", revision)
        with self.store.tx() as conn:
            r = self.store.qone(
                conn, "SELECT MAX(revision) AS m FROM adjudications "
                "WHERE product_id=? AND data_version=?", (product_id, data_version))
            if r is None or r["m"] is None:
                raise DomainError(404, "adjudication_not_found")
            return r["m"]

    def verify_credential(self, body: dict, signature: str) -> bool:
        pub = security.get_public_key_pem(self.store)
        return security.verify_body(pub, body, signature)

    # =====================================================================
    # 合规复核：裁决审计账本（游标读取 / 导出 / 链验真）
    # =====================================================================

    @staticmethod
    def _parse_iso(value: str, param: str) -> str:
        """解析 ISO-8601 时间边界，统一归一化为内部 UTC 文本以便字典序比较。"""
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            raise DomainError(422, "invalid_time_range",
                              {"param": param, "value": value,
                               "message": "时间须为 ISO-8601，如 2026-01-01T00:00:00Z"})
        if dt.tzinfo is None:
            raise DomainError(422, "invalid_time_range",
                              {"param": param, "value": value,
                               "message": "时间必须带时区（建议直接用 Z 结尾的 UTC）"})
        return iso(dt)

    @staticmethod
    def _encode_cursor(token: dict) -> str:
        return _b64e(Store.dumps(token).encode("utf-8"))

    @staticmethod
    def _decode_cursor(cursor: str) -> dict:
        try:
            token = json.loads(_b64d(cursor.encode("ascii")))
        except Exception:
            raise DomainError(400, "invalid_cursor", "审计游标无法解析或已损坏")
        if not isinstance(token, dict) or "v" not in token:
            raise DomainError(400, "invalid_cursor", "审计游标结构不合法")
        return token

    def _resolve_audit_scope(self, conn: sqlite3.Connection, product_id: str,
                             start_at: str | None, end_at: str | None
                             ) -> tuple[str | None, str | None]:
        self._require_product(conn, product_id)
        s = self._parse_iso(start_at, "start_at") if start_at else None
        e = self._parse_iso(end_at, "end_at") if end_at else None
        if s is not None and e is not None and s >= e:
            raise DomainError(422, "invalid_time_range",
                              {"start_at": start_at, "end_at": end_at,
                               "message": "空范围：start_at 必须早于 end_at（半开区间 [start,end)）"})
        return s, e

    def audit_page(self, product_id: str, *, cursor: str | None,
                   page_size: int, start_at: str | None,
                   end_at: str | None) -> AuditPage:
        if page_size < 1 or page_size > 200:
            raise DomainError(422, "invalid_page_size", "page_size 须在 1..200")

        s_raw, e_raw = start_at, end_at
        if cursor:
            token = self._decode_cursor(cursor)
            if token.get("v") != 1:
                raise DomainError(400, "invalid_cursor", "不支持的游标版本")
            if token.get("product_id") != product_id:
                raise DomainError(
                    409, "cursor_product_mismatch",
                    {"cursor_product": token.get("product_id"),
                     "request_product": product_id,
                     "message": "游标绑定另一个产品，审计链不可跨产品分页"})
            after_seq = int(token.get("after_seq", 0))
            if token.get("start_at") != (s_raw or ""):
                raise DomainError(409, "cursor_scope_mismatch",
                                  "游标绑定的 start_at 与当前请求不一致，时间范围不可中途更换")
            if token.get("end_at") != (e_raw or ""):
                raise DomainError(409, "cursor_scope_mismatch",
                                  "游标绑定的 end_at 与当前请求不一致，时间范围不可中途更换")
            if int(token.get("page_size", -1)) != page_size:
                raise DomainError(409, "cursor_scope_mismatch",
                                  "游标绑定的 page_size 与当前请求不一致")
        else:
            after_seq = 0

        with self.store.tx() as conn:
            s, e = self._resolve_audit_scope(conn, product_id, s_raw, e_raw)
            rows = AuditLedger.read_page(
                conn, product_id, after_seq=after_seq, limit=page_size + 1,
                start_at=s, end_at=e)
            tip = AuditLedger.tip(conn, product_id)
            page = rows[:page_size]
            items = [AuditEventOut(**audit.event_out(r)) for r in page]
            next_cursor = None
            if len(rows) > page_size:
                next_cursor = self._encode_cursor({
                    "v": 1, "product_id": product_id,
                    "start_at": s_raw or "", "end_at": e_raw or "",
                    "page_size": page_size, "after_seq": page[-1]["seq"],
                })
            tip_seq = tip["seq"] if tip else 0
        return AuditPage(
            product_id=product_id, page_size=page_size,
            start_at=s_raw, end_at=e_raw, after_seq=after_seq,
            next_cursor=next_cursor, items=items, tip_seq=tip_seq)

    def audit_export(self, product_id: str, *, fmt: str,
                     start_at: str | None, end_at: str | None
                     ) -> tuple[str, str, str]:
        """按时间范围导出全量事件（CSV / JSON）；纯只读，绝不写业务/账本数据。

        返回 (filename, media_type, payload)。
        """
        if fmt not in ("csv", "json"):
            raise DomainError(422, "invalid_export_format",
                              {"format": fmt, "allowed": ["csv", "json"]})
        with self.store.tx() as conn:
            s, e = self._resolve_audit_scope(conn, product_id, start_at, end_at)
            rows = AuditLedger.read_range(
                conn, product_id, start_at=s, end_at=e, from_seq=1)
            events = [audit.event_out(r) for r in rows]
            tip = AuditLedger.tip(conn, product_id)
        tip_seq = tip["seq"] if tip else 0
        tip_digest = tip["digest"] if tip else None

        if fmt == "json":
            doc = {
                "export": "audit-ledger",
                "product_id": product_id,
                "start_at": start_at,
                "end_at": end_at,
                "count": len(events),
                "tip_seq": tip_seq,
                "tip_digest": tip_digest,
                "events": events,
            }
            payload = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True)
            return f"audit-{product_id}.json", "application/json", payload

        import csv
        import io
        buf = io.StringIO()
        cols = ["product_id", "seq", "event_id", "event_type", "object_type",
                "object_id", "actor", "occurred_at", "data_version", "revision",
                "run_id", "credential_id", "exemption_id", "rule_id",
                "prev_digest", "digest", "detail"]
        writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for ev in events:
            row = dict(ev)
            row["detail"] = Store.dumps(ev["detail"])
            writer.writerow(row)
        return f"audit-{product_id}.csv", "text/csv", buf.getvalue()

    def audit_verify(self, product_id: str, from_seq: int = 1) -> AuditChainStatus:
        if not isinstance(from_seq, int) or from_seq < 1:
            raise DomainError(422, "invalid_from_seq",
                              {"from_seq": from_seq, "message": "from_seq 须为 >=1 的整数"})
        with self.store.tx() as conn:
            self._require_product(conn, product_id)
            try:
                result = AuditLedger.verify_chain(conn, product_id, from_seq=from_seq)
            except ValueError as ex:
                raise DomainError(422, "invalid_from_seq", str(ex))
        status = AuditChainStatus(**result)
        if not status.valid:
            # 被篡改的事件链是明确的业务冲突，而非请求格式错误
            raise DomainError(409, "audit_chain_broken", status.model_dump(by_alias=True))
        return status

