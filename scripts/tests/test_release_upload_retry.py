from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleaseUploadRetryTests(unittest.TestCase):
    def run_upload(self, mode: str) -> tuple[subprocess.CompletedProcess[str], int]:
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        start = workflow.index('          push_release_image() {')
        end = workflow.index('\n          }', start) + len('\n          }')
        function = textwrap.dedent(workflow[start:end])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker = root / 'docker'
            docker.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
path = pathlib.Path(os.environ['UPLOAD_COUNTER'])
count = int(path.read_text()) + 1 if path.exists() else 1
path.write_text(str(count))
if os.environ['UPLOAD_MODE'] == 'authorization':
    print('denied: permission_denied: write_package', file=sys.stderr)
    raise SystemExit(1)
if os.environ['UPLOAD_MODE'] == 'always' or count < 3:
    print('unknown blob', file=sys.stderr)
    raise SystemExit(1)
print('published the same scanned image')
''')
            docker.chmod(0o755)
            (root / 'sleep').write_text('#!/bin/sh\nexit 0\n')
            (root / 'sleep').chmod(0o755)
            counter = root / 'count'
            result = subprocess.run(
                ['bash', '-c', function + '\npush_release_image ghcr.io/example/test:8.1.1'],
                env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                     'UPLOAD_COUNTER': str(counter), 'UPLOAD_MODE': mode},
                capture_output=True, text=True, check=False,
            )
            return result, int(counter.read_text())

    def test_transient_unknown_blob_retries_then_succeeds(self) -> None:
        result, attempts = self.run_upload('eventual')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(attempts, 3)

    def test_repeated_transient_failure_stops_after_three_attempts(self) -> None:
        result, attempts = self.run_upload('always')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(attempts, 3)

    def test_authorization_failure_is_not_retried(self) -> None:
        result, attempts = self.run_upload('authorization')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(attempts, 1)


if __name__ == '__main__':
    unittest.main()
