"""HTTP API：规则 API、异常工作台、可下载质量凭据。"""
from __future__ import annotations

import json

from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse

from . import security
from .models import (
    ActivateRule,
    AdjudicationOut,
    CreateProduct,
    CreateRule,
    ExemptionOut,
    FailurePage,
    GrantExemption,
    ProductOut,
    PublishRequest,
    RepairOut,
    RepairRequest,
    ReplayRequest,
    RevokeExemption,
    RuleOut,
    VersionOut,
)
from .service import DomainError, Service
from .storage import Store


def create_app(store: Store | None = None) -> FastAPI:
    app = FastAPI(
        title="数据质量规则版本化执行与回溯裁决平台",
        version="1.0.0",
        description=(
            "固定快照发布、规则版本化执行、历史回放只生成修订版；"
            "发布冻结不可改写；豁免绑定精确样本与规则摘要；"
            "分页读取固定结果快照；冻结后签发可下载质量凭据。"
        ),
    )
    app.state.store = store or Store()
    app.state.service = Service(app.state.store)

    @app.exception_handler(DomainError)
    async def domain_error_handler(_: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.error, "detail": exc.detail},
        )

    def svc(request: Request) -> Service:
        return request.app.state.service

    # ---------------- 数据产品 ----------------

    @app.post("/products", response_model=ProductOut, status_code=201,
              tags=["数据产品"])
    def create_product(req: CreateProduct, service: Service = Depends(svc)):
        return service.create_product(req)

    @app.get("/products", tags=["数据产品"])
    def list_products(service: Service = Depends(svc)):
        return service.list_products()

    @app.get("/products/{product_id}", response_model=ProductOut, tags=["数据产品"])
    def get_product(product_id: str, service: Service = Depends(svc)):
        return service.get_product(product_id)

    @app.get("/products/{product_id}/versions",
             response_model=list[VersionOut], tags=["数据产品"])
    def list_versions(product_id: str, service: Service = Depends(svc)):
        return service.list_versions(product_id)

    @app.post("/products/{product_id}/repair",
              response_model=RepairOut, tags=["数据产品-数据修复"],
              summary="修复数据（仅暂存区，不影响任何已发布快照）")
    def repair(product_id: str, req: RepairRequest, service: Service = Depends(svc)):
        return service.repair(product_id, req.actor, req.note, req.upserts, req.deletes)

    @app.post("/products/{product_id}/publish",
              response_model=AdjudicationOut, tags=["数据产品-发布"],
              status_code=201,
              summary="发布新固定快照并按当前激活规则形成第 1 版裁决")
    def publish(product_id: str, req: PublishRequest, service: Service = Depends(svc)):
        return service.publish(product_id, req.actor, req.note)

    @app.post("/products/{product_id}/freeze",
              response_model=AdjudicationOut, tags=["数据产品-发布冻结"],
              summary="冻结最新修订版的发布判断并签发质量凭据（幂等）")
    def freeze(product_id: str, data_version: int | None = Query(default=None),
               service: Service = Depends(svc)):
        out, _, _ = service.freeze(product_id, data_version)
        return out

    # ---------------- 规则 API ----------------

    @app.post("/rules", response_model=RuleOut, status_code=201, tags=["规则 API"])
    def create_rule(req: CreateRule, service: Service = Depends(svc)):
        return service.create_rule(req)

    @app.get("/products/{product_id}/rules",
             response_model=list[RuleOut], tags=["规则 API"])
    def list_rules(product_id: str, service: Service = Depends(svc)):
        return service.list_rules(product_id)

    @app.get("/rules/{rule_id}", response_model=RuleOut, tags=["规则 API"])
    def get_rule(rule_id: str, service: Service = Depends(svc)):
        return service.get_rule(rule_id)

    @app.post("/rules/{rule_id}/versions",
              response_model=RuleOut, status_code=201, tags=["规则 API"],
              summary="规则升级：新增不可变版本并自动成为激活版")
    def add_rule_version(rule_id: str, req: CreateRule,
                         service: Service = Depends(svc)):
        # body.product_id 以路径规则所属产品为准，防止跨产品引用
        rule = service.get_rule(rule_id)
        if req.product_id != rule.product_id:
            raise DomainError(409, "product_mismatch",
                              {"rule_product": rule.product_id,
                               "body_product": req.product_id})
        return service.add_rule_version(rule_id, req.kind, req.config)

    @app.post("/rules/{rule_id}/activate",
              response_model=RuleOut, tags=["规则 API"],
              summary="切换激活规则版本（仅影响此后的新发布/回放）")
    def activate_rule(rule_id: str, req: ActivateRule, service: Service = Depends(svc)):
        return service.activate_rule(rule_id, req.version)

    @app.post("/products/{product_id}/replay",
              response_model=AdjudicationOut, status_code=201,
              tags=["规则 API-回放"],
              summary="对最新发布快照回放规则；只生成新修订版，不改写历史判断")
    def replay(product_id: str, req: ReplayRequest, service: Service = Depends(svc)):
        return service.replay(product_id, req)

    # ---------------- 裁决 ----------------

    @app.get("/products/{product_id}/adjudications",
             response_model=list[AdjudicationOut], tags=["裁决"],
             summary="列出某数据版本的全部修订版裁决（默认最新版本）")
    def list_adjudications(product_id: str,
                           data_version: int | None = Query(default=None),
                           service: Service = Depends(svc)):
        return service.list_adjudications(product_id, data_version)

    @app.get("/runs/{run_id}", response_model=AdjudicationOut, tags=["裁决"],
             summary="按 run_id 读取其所属修订版裁决")
    def adjudication_by_run(run_id: str, service: Service = Depends(svc)):
        return service.adjudication_by_run(run_id)

    # ---------------- 失败样本（固定快照分页） ----------------

    @app.get("/runs/{run_id}/failures",
             response_model=FailurePage, tags=["失败样本"],
             summary="分页读取失败样本；游标绑定 run_id，只能读取同一固定结果快照")
    def list_failures(run_id: str,
                      cursor: str | None = Query(default=None),
                      page_size: int = Query(default=50, ge=1, le=200),
                      service: Service = Depends(svc)):
        return service.failures_page(run_id, cursor, page_size)

    # ---------------- 异常工作台 ----------------

    @app.post("/exemptions", response_model=ExemptionOut, status_code=201,
              tags=["异常工作台"],
              summary="对精确 (run 内失败样本, 规则指纹) 授予豁免；冻结裁决不可追加")
    def grant_exemption(req: GrantExemption, service: Service = Depends(svc)):
        return service.grant_exemption(
            req.run_id, req.ordinal, req.actor, req.reason, req.ttl_seconds)

    @app.post("/exemptions/{exemption_id}/revoke",
              response_model=ExemptionOut, tags=["异常工作台"],
              summary="撤销豁免；不影响已冻结凭据中的豁免副本")
    def revoke_exemption(exemption_id: str, req: RevokeExemption,
                         service: Service = Depends(svc)):
        return service.revoke_exemption(exemption_id, req.actor, req.reason)

    @app.get("/products/{product_id}/exemptions",
             tags=["异常工作台"],
             summary="分页查看豁免（游标分页）")
    def list_exemptions(product_id: str,
                        data_version: int | None = Query(default=None),
                        status_filter: str | None = Query(default=None, alias="status"),
                        page_size: int = Query(default=50, ge=1, le=200),
                        cursor: str | None = Query(default=None),
                        service: Service = Depends(svc)):
        items, next_cursor = service.list_exemptions(
            product_id, data_version, status_filter, page_size, cursor)
        return {"page_size": page_size, "next_cursor": next_cursor,
                "items": [i.model_dump() for i in items]}

    # ---------------- 质量凭据 ----------------

    @app.get("/products/{product_id}/credentials/{data_version}/latest",
             tags=["质量凭据"],
             summary="下载最新修订版的质量凭据（JSON 文件，含签名）")
    def credential_latest(product_id: str, data_version: int,
                          service: Service = Depends(svc)):
        revision = service.resolve_revision(product_id, data_version, "latest")
        return _credential_file(service, product_id, data_version, revision)

    @app.get("/products/{product_id}/credentials/{data_version}/{revision}",
             tags=["质量凭据"],
             summary="下载指定修订版的质量凭据（JSON 文件，含签名）")
    def credential_revision(product_id: str, data_version: int, revision: int,
                            service: Service = Depends(svc)):
        return _credential_file(service, product_id, data_version, revision)

    def _credential_file(service: Service, product_id: str,
                         data_version: int, revision: int) -> Response:
        body, signature = service.get_credential(product_id, data_version, revision)
        envelope = {
            "body": body,
            "signature": signature,
            "algorithm": "Ed25519",
            "canonicalization": "JCS-style sort_keys compact UTF-8 JSON",
            "verify": {
                "public_key_endpoint": "/credentials/public-key",
                "verify_endpoint": "/credentials/verify",
            },
        }
        payload = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True)
        fname = f"dq-credential-{product_id}-v{data_version}-r{revision}.json"
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @app.get("/credentials/public-key", tags=["质量凭据"],
             summary="获取验签公钥（PEM）")
    def public_key(request: Request):
        import base64
        pem = base64.b64decode(
            security.get_public_key_pem(request.app.state.store)).decode("ascii")
        return {"algorithm": "Ed25519", "public_key_pem": pem}

    @app.post("/credentials/verify", tags=["质量凭据"],
              summary="凭据验签（body + signature）")
    def verify_credential(payload: dict, request: Request):
        body = payload.get("body")
        signature = payload.get("signature")
        if not isinstance(body, dict) or not isinstance(signature, str):
            raise DomainError(422, "invalid_payload", "需要 body(dict) 与 signature(str)")
        ok = request.app.state.service.verify_credential(body, signature)
        return {"valid": ok} if ok else JSONResponse(
            status_code=400, content={"valid": False, "error": "invalid_signature"})

    @app.get("/health", tags=["运维"])
    def health():
        return {"status": "ok"}

    return app


app = create_app()
