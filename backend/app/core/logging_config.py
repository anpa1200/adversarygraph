from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.core.config import settings

_CONFIGURED_ATTR = "_adversarygraph_logging_configured"


def configure_logging() -> None:
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    log_dir = Path(settings.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)

    if getattr(root, _CONFIGURED_ATTR, False):
        for handler in root.handlers:
            if getattr(handler, "_adversarygraph_handler", False):
                handler.setLevel(level)
        return

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s request_id=%(request_id)s %(message)s"
    )

    class RequestIdFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            if not hasattr(record, "request_id"):
                record.request_id = "-"
            return True

    console_handler = logging.StreamHandler(sys.stdout)
    file_handler = RotatingFileHandler(
        log_dir / "adversarygraph-api.log",
        maxBytes=settings.log_max_bytes,
        backupCount=settings.log_backup_count,
        encoding="utf-8",
    )

    for handler in (console_handler, file_handler):
        handler.setLevel(level)
        handler.setFormatter(formatter)
        handler.addFilter(RequestIdFilter())
        setattr(handler, "_adversarygraph_handler", True)
        root.addHandler(handler)

    setattr(root, _CONFIGURED_ATTR, True)
    logging.getLogger(__name__).info(
        "AdversaryGraph logging configured: dir=%s level=%s", log_dir, settings.log_level
    )
