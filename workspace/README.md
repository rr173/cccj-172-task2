# 数据质量规则版本化执行与回溯裁决平台

固定快照发布、规则版本化执行、历史回放只产生修订版；发布冻结不可改写；
异常豁免绑定精确样本与规则摘要；分页只读固定结果快照；冻结后签发
**可下载、可离线验签的质量凭据（Ed25519）**。

## 领域模型与核心不变量

```
产品(固定表结构)
 ├─ 数据版本 data_version   ← 发布时由暂存区整体冻结，snapshot_rows 永不可变
 │    └─ 裁决修订版 revision
 │         ├─ rev1 = 发布当刻规则集执行结果（run，不可变）
 │         ├─ rev2.. = 规则升级后对同一历史快照回放产生（open，互不覆盖）
 │         └─ 冻结后物化计数+豁免副本 → 质量凭据（Ed25519 签名）
 └─ 规则 rule
      ├─ v1/v2/v3 … 定义不可变，配置哈希即 rule_fingerprint
      └─ active_version 只影响此后的新发布/回放
```

1. **快照不可变**：数据修复只写暂存区；发布把暂存区整体复制为新
   `data_version`，之后任何修复都不触碰历史快照。
2. **回放不覆盖**：规则升级后对历史快照回放，只生成新的 `revision`；
   原修订版的 run、失败样本、发布判断保持原样。同一规则集对同一快照
   禁止重复回放（`409 ruleset_already_adjudicated`）。
3. **冻结即终局**：冻结把当时的有效豁免集合与（总失败/豁免/有效失败）
   计数物化进裁决与凭据正文并签名。事后撤销/新增豁免、再回放都改不了
   冻结结论；冻结裁决上追加豁免直接 `409 adjudication_frozen`。
4. **豁免精确绑定**：豁免唯一键为
   `(product, data_version, rule_fingerprint, sample_fingerprint)`，
   其中样本摘要 = `SHA256(table + ' ' + row_pk)`。规则升级后指纹改变，
   旧豁免不会抑制新 run 上的同样本失败。
5. **分页固定快照**：游标是 base64 的 `{run_id, ordinal}`，跨 run 使用
   游标返回 `409 cursor_snapshot_mismatch`；run_failures 只追加，翻页
   视图稳定。
6. **并发安全**：SQLite WAL + 进程写锁 + 全部写事务 `BEGIN IMMEDIATE`，
   修复/回放/冻结/豁免四类写操作串行化（见
   `tests/test_platform.py::test_concurrent_mixed_writes_are_serialized`）。
7. **裁决审计账本（仅追加哈希链）**：数据修复、规则登记/升级/激活、
   发布裁决、回放形成修订、豁免授予/撤销、冻结、凭据签发，每一个动作都在
   **同一写事务内**向 `audit_events` 追加一条不可修改事件；事务回滚则
   事件一并回滚。链按产品独立、`seq` 从 1 连续递增，每条事件携带
   `prev_digest`，本事件 `digest = SHA256(canonical(全部字段 + prev_digest))`，
   带外删除/改写任何字段都会在验真时按序号精确报出断点。服务层没有任何
   更新/删除账本的代码路径。

## 规则类型

| kind | 配置 | 失败样本定位 |
|---|---|---|
| `not_null` | table, column | 行 |
| `unique` | table, columns[] | 重复侧行（NULL 不参与） |
| `value_range` | table, column, min/max（闭区间） | 行 |
| `cross_field` | table, left, op(lt/le/gt/ge/eq/ne), right | 行 |
| `cross_table` | left_table, left_columns[], right_table, right_columns[] | 孤儿侧行 |

每条失败记录：`rule_id / rule_version / rule_fingerprint / table /
row_pk / sample_fingerprint / detail`。

## 快速开始

```bash
pip install -r requirements.txt
python3 -m app.main                 # http://localhost:8080  （/docs 为交互文档）
# 或
DQ_DB_PATH=/tmp/dq.db uvicorn app.api:app --port 8080
```

端到端演练（另见 `scripts/demo.py`）：

```bash
python3 scripts/demo.py
```

## 主要 API

| 方法 & 路径 | 说明 |
|---|---|
| `POST /products` | 建产品（固定字段/主键） |
| `POST /products/{id}/repair` | 数据修复（仅暂存区，带类型/非空校验） |
| `POST /products/{id}/publish` | 发布新固定快照 + rev1 裁决 |
| `POST /rules` / `POST /rules/{id}/versions` / `POST /rules/{id}/activate` | 规则与版本管理（升级不可改类型、不可重复指纹） |
| `POST /products/{id}/replay` | 对最新快照回放（当前激活集或显式 `rule_versions`） |
| `GET /products/{id}/adjudications?data_version=` | 修订版裁决链 |
| `GET /runs/{run_id}/failures?cursor=&page_size=` | 失败样本分页（固定 run 快照） |
| `POST /exemptions` / `POST /exemptions/{id}/revoke` | 异常工作台 |
| `GET /products/{id}/exemptions` | 豁免分页 |
| `POST /products/{id}/freeze?data_version=` | 冻结调用时刻最新修订版（幂等） |
| `GET /products/{id}/credentials/{dv}/{rev}` | 下载质量凭据 JSON（含签名） |
| `GET /products/{id}/credentials/{dv}/latest` | 最新修订版凭据 |
| `GET /credentials/public-key` / `POST /credentials/verify` | 验签 |

### 裁决审计账本（合规复核）

| 方法 & 路径 | 说明 |
|---|---|
| `GET /products/{id}/audit/events?start_time=&end_time=&page_size=&cursor=` | 按产品 + 时间范围（半开区间，ISO-8601）游标读取事件 |
| `GET /products/{id}/audit/export?start_seq=&end_seq=&fmt=json\|csv` | 按事件序号区间导出 JSON 或 CSV 文件 |
| `GET /products/{id}/audit/verify?start_seq=&end_seq=` | 从任意序号重算摘要链验真，断点精确到序号 |

事件类型：`data_repaired` / `rule_registered` / `rule_upgraded` /
`rule_activated` / `adjudication_published` / `revision_requested`（再次请求
回放形成修订）/ `exemption_granted` / `exemption_revoked` /
`adjudication_frozen` / `credential_issued`。

每条事件包含：事件类型、业务对象（`object_type` + `object_ref`）、操作者
`actor`、时间 `occurred_at`、关联 `data_version` / `revision` / `run_id` /
`credential_id`、事件细节 `payload`、`prev_digest` 与本事件 `digest`。

**游标语义**：游标是 base64 的
`{p:产品, a:起始 after_seq, s/e:时间范围, ps:页大小}`，按
`(product_id, seq)` keyset 翻页；账本只追加，期间并发写入不会让翻页
丢事件或重复事件，重试同一游标返回同一页。明确错误：非法游标
`400 invalid_cursor`、跨产品游标 `409 cursor_product_mismatch`、
游标时间范围与请求不一致 `409 cursor_scope_mismatch`、空范围
`404 audit_empty_range`。

**验真**：逐链环核对 seq 连续性、`prev_digest` 与重算摘要；断裂返回
`409 audit_chain_broken`，`detail.kind` 为 `missing_event`（删除致空洞）、
`prev_digest_mismatch` / `genesis_mismatch`（链指针被伪造）或
`digest_mismatch`（字段/payload 被篡改），并给出 `seq`、存储值与重算值。
`start_seq>1` 时以 `start_seq-1` 的已存摘要为锚点，可对任意子链验真。
导出与验真均为只读，绝不改变业务数据、裁决状态，也不产生新审计事件。

## 质量凭据格式

下载文件为

```json
{
  "body": {
    "credential_id": "...", "product_id": "...", "data_version": 1,
    "revision": 2, "run_id": "...", "status": "frozen",
    "schema_fingerprint": "...", "ruleset_fingerprint": "...",
    "verdict": "fail",
    "failure_count": 4, "suppressed_count": 1, "effective_count": 3,
    "rules": [ {"rule_id","rule_version","rule_fingerprint","kind","config"} ],
    "active_exemptions": [ {"rule_fingerprint","sample_fingerprint","table_name","row_pk", ...} ],
    "published_at": "...", "frozen_at": "..."
  },
  "signature": "<base64 Ed25519>",
  "algorithm": "Ed25519",
  "canonicalization": "JCS-style sort_keys compact UTF-8 JSON"
}
```

签名覆盖规范化后的 `body`；公钥由 `/credentials/public-key` 公布，
任何拿到凭据的一方可用 `POST /credentials/verify` 或标准 Ed25519 库
离线验签，证明裁决在冻结时刻由本平台签发且正文未被篡改。

## 测试

```bash
python3 -m pytest -q
```

覆盖：快照不可变、修复隔离、规则升级回放修订链、重复回放拒绝、
冻结物化解耦事后豁免、凭据签名/篡改检测、豁免精确绑定与 TTL、
游标跨快照拒绝、四类操作并发交错、各规则引擎定位，以及审计账本：
全动作同事务落账、游标并发写入不丢不重与重试幂等、跨产品/非法/范围
不一致游标与空范围错误、JSON/CSV 只读导出、摘要链验真与各类断点精确定位。
