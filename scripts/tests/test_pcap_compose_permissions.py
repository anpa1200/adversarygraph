"""Regression guard for the non-root PCAP storage initialization contract."""
import re
import unittest
from pathlib import Path


class PcapStoragePermissionsTest(unittest.TestCase):
    def test_initializer_can_chmod_after_chown(self):
        compose = (Path(__file__).resolve().parents[2] / 'docker-compose.yml').read_text()
        service = compose.split('  pcap-storage-permissions:\n', 1)[1].split('\n  pcap-analyzer:', 1)[0]
        self.assertIn('chown -R 999:999 /app/data/pcap', service)
        self.assertIn('chmod 0700 /app/data/pcap', service)
        # Once chown changes the owner, root requires FOWNER for chmod when
        # all capabilities have been dropped. DAC_OVERRIDE alone is not enough.
        self.assertRegex(service, re.compile(r'cap_add:\n(?:      - \w+\n)*      - FOWNER\n'))
        decoder = compose.split('  pcap-analyzer:\n', 1)[1].split('\n  # Initialize', 1)[0]
        self.assertIn('cap_drop:\n      - ALL', decoder)
        self.assertNotIn('cap_add:', decoder)


if __name__ == '__main__':
    unittest.main()
