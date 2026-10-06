"""运行期配置。"""
from __future__ import annotations

import os

DEFAULT_DB_PATH = os.environ.get("DQ_DB_PATH", "/tmp/dq_platform.db")
