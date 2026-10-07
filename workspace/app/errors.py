"""领域错误类型（独立模块，避免 service/audit 循环导入）。"""
from __future__ import annotations

from typing import Any


class DomainError(Exception):
    def __init__(self, status_code: int, error: str, detail: Any = None):
        super().__init__(error)
        self.status_code = status_code
        self.error = error
        self.detail = detail
