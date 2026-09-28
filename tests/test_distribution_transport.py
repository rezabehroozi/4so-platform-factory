import importlib.util, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("transport",ROOT/"scripts"/"distribution_transport.py")
mod=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)

class DistributionTransportTests(unittest.TestCase):
    def test_split_reassemble_and_locator_contract(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/"source.bin"; source.write_bytes((b"0123456789abcdef"*1024)+b"tail")
            parts_dir=root/"parts"
            manifest=mod.split_file(source,parts_dir,max_part_bytes=4096,name="appliance.zip")
            locator={"parts":[]}
            for row in manifest["parts"]:
                locator["parts"].append({"index":row["index"],"urls":[f"https://dist.example.test/sha256/{row['sha256']}/{row['fileName']}"],"sha256":row["sha256"],"sizeBytes":row["sizeBytes"]})
            checked=mod.validate_locator(locator,expected_sha256=manifest["sha256"],expected_size=manifest["sizeBytes"],label="PACK")
            self.assertEqual(len(manifest["parts"]),len(checked["parts"]))
            out=root/"joined.bin"; mod.reassemble_files(manifest["parts"],parts_dir,out,expected_sha256=manifest["sha256"],expected_size=manifest["sizeBytes"])
            self.assertEqual(source.read_bytes(),out.read_bytes())

    def test_direct_or_parts_is_exclusive(self):
        digest="a"*64
        with self.assertRaisesRegex(RuntimeError,"TRANSPORT_MODE"):
            mod.validate_locator({"urls":[f"https://x.example/sha256/{digest}/x"],"parts":[]},expected_sha256=digest,expected_size=1,label="X")
        with self.assertRaisesRegex(RuntimeError,"TRANSPORT_MODE"):
            mod.validate_locator({},expected_sha256=digest,expected_size=1,label="X")

    def test_part_index_sum_and_content_address_are_fail_closed(self):
        a="a"*64; b="b"*64
        good={"parts":[{"index":0,"urls":[f"https://dist.example/sha256/{a}/p0"],"sha256":a,"sizeBytes":2},{"index":1,"urls":[f"https://dist.example/sha256/{b}/p1"],"sha256":b,"sizeBytes":3}]}
        mod.validate_locator(good,expected_sha256="c"*64,expected_size=5,label="OBJ")
        bad={"parts":[dict(good["parts"][0]),dict(good["parts"][1])]}
        bad["parts"][1]["index"]=2
        with self.assertRaisesRegex(RuntimeError,"INDEX"): mod.validate_locator(bad,expected_sha256="c"*64,expected_size=5,label="OBJ")
        bad={"parts":[dict(good["parts"][0]),dict(good["parts"][1])]}
        bad["parts"][1]["sizeBytes"]=4
        with self.assertRaisesRegex(RuntimeError,"SIZE_SUM"): mod.validate_locator(bad,expected_sha256="c"*64,expected_size=5,label="OBJ")
        bad={"parts":[dict(good["parts"][0]),dict(good["parts"][1])]}
        bad["parts"][0]["urls"]=["https://dist.example/not-content-addressed/p0"]
        with self.assertRaisesRegex(RuntimeError,"CONTENT_ADDRESS"): mod.validate_locator(bad,expected_sha256="c"*64,expected_size=5,label="OBJ")

if __name__=="__main__": unittest.main()
