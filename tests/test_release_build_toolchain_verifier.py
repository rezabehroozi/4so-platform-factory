import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('verify_release_build_toolchain',ROOT/'scripts'/'verify_release_build_toolchain.py')
MOD=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MOD)

class ReleaseBuildToolchainVerifierTests(unittest.TestCase):
    def test_current_go_uses_explicit_go_authority_from_environment(self):
        completed=mock.Mock(returncode=0,stdout='go version go1.27.1 linux/amd64\n',stderr='')
        with mock.patch.dict(MOD.os.environ,{'GO':'/opt/4so/go1.27.1/bin/go'},clear=False):
            with mock.patch.object(MOD.subprocess,'run',return_value=completed) as run:
                rc,active=MOD.current_go()
        self.assertEqual((0,'go version go1.27.1 linux/amd64'),(rc,active))
        run.assert_called_once_with(['/opt/4so/go1.27.1/bin/go','version'],text=True,capture_output=True)

if __name__=='__main__': unittest.main()
