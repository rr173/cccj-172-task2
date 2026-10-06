"""本地启动入口：

    DQ_DB_PATH=/tmp/dq.db python3 -m app.main
    # 或 uvicorn app.api:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import uvicorn

from .config import DEFAULT_DB_PATH
from .api import create_app
from .storage import Store


def main() -> None:
    store = Store(DEFAULT_DB_PATH)
    app = create_app(store)
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")


if __name__ == "__main__":
    main()
