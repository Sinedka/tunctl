"""Exercise the installed-path substitutions without touching host networking."""
import json
import runpy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


class NativePolicyTests(unittest.TestCase):
    def setUp(self):
        self.net = runpy.run_path(HELPER)
        self.config = json.loads((PACKAGING / "policy.example.json").read_text())

    def render(self):
        generate = self.net["ruleset"]
        with patch.dict(generate.__globals__, TEMPLATE=PACKAGING / "routing.nft.in"):
            return generate(self.config)

    def test_filter_and_address_families(self):
        self.config.update(killSwitch=True, directIPs=["10.1.2.3/8", "2001:db8::1"])
        batch = self.render()
        self.assertIn(self.net["GUARD"], batch)
        self.assertIn("ip daddr 10.0.0.0/8", batch)
        self.assertIn("ip6 daddr 2001:db8::1/128", batch)
        self.assertNotIn("%DIRECT_IPS%", batch)
        self.assertNotIn("flush ruleset", batch)
        self.config["killSwitch"] = False
        self.assertNotIn(self.net["GUARD"], self.render())

    def test_invalid_policy(self):
        for key, value in (("directIPs", ["not-an-address"]), ("killSwitch", "false"),
                           ("policyUser", "unauthorized")):
            with self.subTest(key=key):
                self.config = json.loads((PACKAGING / "policy.example.json").read_text())
                self.config[key] = value
                with self.assertRaises(ValueError):
                    self.render()


if __name__ == "__main__":
    HELPER, PACKAGING = sys.argv[1], Path(sys.argv[2])
    unittest.main(argv=[sys.argv[0]])
