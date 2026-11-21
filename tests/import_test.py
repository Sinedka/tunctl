import importlib.util
import pathlib
import tempfile
import unittest
import zipfile
import sys

spec = importlib.util.spec_from_file_location("profile_import", pathlib.Path(__file__).parents[1] / "src/import.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ImportTests(unittest.TestCase):
    def test_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = pathlib.Path(temp) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("../escape.ovpn", "client")
            with self.assertRaises(ValueError):
                module.main(archive)
            self.assertFalse((archive.parent.parent / "escape.ovpn").exists())

    def test_bundle(self):
        files = {"sub/p.ovpn": b'ca "pki/root ca.crt"\ntls-auth ta.key 1', "sub/pki/root ca.crt": b"CERT", "sub/ta.key": b"KEY"}
        result = module.expand(pathlib.PurePosixPath("sub/p.ovpn"), lambda n: files[str(n)])
        self.assertIn("<ca>\nCERT\n</ca>", result)
        self.assertIn("key-direction 1", result)

    def test_escaping_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / "key").symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                module.local(root, "key")


if __name__ == "__main__":
    unittest.main()
