"""API 请求 / 响应模型。"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


# ---------- 数据产品 ----------

class ColumnDef(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    type: Literal["string", "integer", "number", "boolean"]
    nullable: bool = True


class TableDef(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    pk_column: str = Field(min_length=1, max_length=64)
    columns: list[ColumnDef] = Field(min_length=1)


class CreateProduct(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    tables: list[TableDef] = Field(min_length=1)


class RepairRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=64)
    note: str = Field(default="", max_length=512)
    upserts: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    deletes: dict[str, list[str]] = Field(default_factory=dict)


class PublishRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=64)
    note: str = Field(default="", max_length=512)


class ProductOut(BaseModel):
    product_id: str
    name: str
    created_at: str
    tables: list[TableDef]


class VersionOut(BaseModel):
    product_id: str
    data_version: int
    schema_fingerprint: str
    created_at: str


class RepairOut(BaseModel):
    event_id: str
    base_version: int
    upserts: int
    deletes: int
    created_at: str


# ---------- 规则 ----------

RuleKind = Literal[
    "not_null",
    "unique",
    "value_range",
    "cross_field",
    "cross_table",
]


class CreateRule(BaseModel):
    product_id: str
    name: str = Field(min_length=1, max_length=128)
    kind: RuleKind
    config: dict[str, Any]


class RuleVersionOut(BaseModel):
    rule_id: str
    version: int
    kind: RuleKind
    config: dict[str, Any]
    fingerprint: str
    is_active: bool
    created_at: str


class RuleOut(BaseModel):
    rule_id: str
    product_id: str
    name: str
    active_version: int
    versions: list[RuleVersionOut]


class ActivateRule(BaseModel):
    version: int = Field(ge=1)


class ReplayRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=64)
    rule_versions: dict[str, int] | None = None  # rule_id -> version；缺省用当前激活版


# ---------- 裁决 / 失败样本 ----------

class FailureOut(BaseModel):
    ordinal: int
    rule_id: str
    rule_version: int
    rule_fingerprint: str
    table_name: str
    row_pk: str
    sample_fingerprint: str
    detail: dict[str, Any]
    suppressed: bool
    suppression: dict[str, Any] | None = None


class FailurePage(BaseModel):
    run_id: str
    product_id: str
    data_version: int
    revision: int
    adjudication_status: Literal["open", "frozen"]
    page_size: int
    next_cursor: str | None
    items: list[FailureOut]
    snapshot_note: str = "本页及后续页始终读取同一固定 run_id 结果快照，期间任何写入不影响视图"


class AdjudicationOut(BaseModel):
    product_id: str
    data_version: int
    revision: int
    run_id: str
    status: Literal["open", "frozen"]
    trigger: Literal["publish", "replay"]
    ruleset_fingerprint: str
    failure_count: int
    suppressed_count: int
    effective_count: int
    verdict: Literal["pass", "fail"]
    published_at: str
    frozen_at: str | None = None
    credential_id: str | None = None


# ---------- 豁免 ----------

class GrantExemption(BaseModel):
    run_id: str
    ordinal: int
    actor: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=512)
    ttl_seconds: int | None = Field(default=None, ge=1, le=31_536_000)


class ExemptionOut(BaseModel):
    exemption_id: str
    product_id: str
    data_version: int
    rule_id: str
    rule_version: int
    rule_fingerprint: str
    sample_fingerprint: str
    table_name: str
    row_pk: str
    reason: str
    actor: str
    status: Literal["active", "revoked"]
    expires_at: str | None
    created_at: str
    revoked_at: str | None = None


class RevokeExemption(BaseModel):
    actor: str = Field(min_length=1, max_length=64)
    reason: str = Field(default="", max_length=512)


# ---------- 凭据 ----------

class CredentialOut(BaseModel):
    credential_id: str
    product_id: str
    data_version: int
    revision: int
    body: dict[str, Any]
    signature: str
    created_at: str
    verify_url: str


# ---------- 合规复核：裁决审计账本 ----------

AuditEventType = Literal[
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
]


class AuditEventOut(BaseModel):
    product_id: str
    seq: int
    event_id: str
    event_type: AuditEventType
    object_type: str
    object_id: str | None = None
    actor: str
    occurred_at: str
    data_version: int | None = None
    revision: int | None = None
    run_id: str | None = None
    credential_id: str | None = None
    exemption_id: str | None = None
    rule_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    prev_digest: str
    digest: str


class AuditPage(BaseModel):
    product_id: str
    page_size: int
    start_at: str | None = None
    end_at: str | None = None
    after_seq: int
    next_cursor: str | None = None
    tip_seq: int
    items: list[AuditEventOut]
    snapshot_note: str = (
        "游标绑定固定读取起点(产品/时间范围/页大小/after_seq)；"
        "事件只追加且序号永不复用，并发写入不会让翻页丢事件或重复事件，"
        "重试同一游标返回同一页")


class AuditChainStatus(BaseModel):
    valid: bool
    product_id: str
    from_seq: int
    checked: int
    tip_seq: int
    tip_digest: str | None = None
    break_: dict[str, Any] | None = Field(default=None, alias="break")

    model_config = {"populate_by_name": True}


class ErrorOut(BaseModel):
    error: str
    detail: Any = None
