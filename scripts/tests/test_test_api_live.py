from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "test-api-live.py"
SPEC = importlib.util.spec_from_file_location("test_api_live", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import setup guard
    raise RuntimeError(f"Could not load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LoadOpenApiSchemaTests(unittest.TestCase):
    def test_retries_transient_proxy_failure(self) -> None:
        responses = [
            (502, b"Bad Gateway", "text/html"),
            (200, b'{"info": {"version": "6.5.0"}, "paths": {}}', "application/json"),
        ]

        with (
            patch.object(MODULE, "request", side_effect=responses) as request,
            patch.object(MODULE.time, "sleep") as sleep,
        ):
            schema = MODULE.load_openapi_schema(
                "http://127.0.0.1:3000",
                token="",
                timeout=20,
                attempts=3,
                retry_delay=0.25,
            )

        self.assertEqual(schema["info"]["version"], "6.5.0")
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(0.25)

    def test_fails_fast_for_non_transient_http_status(self) -> None:
        with (
            patch.object(
                MODULE,
                "request",
                return_value=(404, b"Not Found", "text/plain"),
            ) as request,
            patch.object(MODULE.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(RuntimeError, "HTTP 404"):
                MODULE.load_openapi_schema(
                    "http://127.0.0.1:3000",
                    token="",
                    timeout=20,
                    attempts=4,
                    retry_delay=1,
                )

        request.assert_called_once()
        sleep.assert_not_called()

    def test_retries_invalid_startup_payload(self) -> None:
        responses = [
            (200, b"<html>starting</html>", "text/html"),
            (200, b'{"paths": {}}', "application/json"),
        ]

        with (
            patch.object(MODULE, "request", side_effect=responses),
            patch.object(MODULE.time, "sleep") as sleep,
        ):
            schema = MODULE.load_openapi_schema(
                "http://127.0.0.1:3000",
                token="",
                timeout=20,
                attempts=2,
                retry_delay=0,
            )

        self.assertEqual(schema, {"paths": {}})
        sleep.assert_called_once_with(0)


if __name__ == "__main__":
    unittest.main()
