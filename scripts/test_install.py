"""Installer regressions using the real Apple compiler, without installing an agent."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "darwin", "requires macOS developer tools")
class InstallerBuild(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kcwho build test ")
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        (self.project / "scripts").mkdir()
        source = Path(__file__).resolve().parents[1]
        for name in ("scripts/install.sh", "kcwatch.swift"):
            shutil.copy2(source / name, self.project / name)

    def build(self, **environment):
        return subprocess.run(
            ["/bin/bash", str(self.project / "scripts/install.sh"), "build"],
            env={**os.environ, **environment}, capture_output=True, text=True,
            timeout=120,
        )

    def test_broken_swiftly_on_path_does_not_block_build(self):
        shim_dir = self.project / "shim"
        shim_dir.mkdir()
        shim = shim_dir / "swiftc"
        shim.write_text(
            "#!/bin/sh\n"
            'echo "Toolchain Swift 6.2.4 could not be located" >&2\n'
            "exit 1\n"
        )
        shim.chmod(0o755)
        result = self.build(
            PATH=f"{shim_dir}:/usr/bin:/bin:/usr/sbin:/sbin",
            TOOLCHAINS="missing-swiftly-toolchain",
            SDKROOT="/missing-sdk",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(os.access(self.project / "build/kcwatch", os.X_OK))

    def test_missing_developer_tools_explains_setup(self):
        result = self.build(
            PATH="/usr/bin:/bin:/usr/sbin:/sbin",
            DEVELOPER_DIR=str(self.project / "missing developer tools"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("xcode-select --install", result.stdout + result.stderr)
        self.assertIn("xcode-select --switch", result.stdout + result.stderr)
        self.assertFalse((self.project / "build/kcwatch").exists())


if __name__ == "__main__":
    unittest.main()
