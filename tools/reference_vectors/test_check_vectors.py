import contextlib
import io
import json
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path

import check_vectors


class XerComparisonTest(unittest.TestCase):
    def test_supported_values_match_and_differences_are_detected(self):
        cases = [
            ("<x><a>2</a></x>", {"a": 2}),
            ("<x><i>1</i><i>2</i></x>", [1, 2]),
            ("<x><a>2</a></x>", ("a", 2)),
            ("<x>101</x>", (5, 3)),
            ("<x/>", (0, 0)),
            ("<x><true/></x>", True),
            ("<x><false/></x>", False),
            ("<x> 2 </x>", 2),
            ("<x><ready/></x>", "ready"),
            ("<x>text</x>", "text"),
            ("<x> AB 10 </x>", bytes.fromhex("ab10")),
        ]
        for xml, value in cases:
            with self.subTest(xml=xml):
                errors = []
                check_vectors.compare(ElementTree.fromstring(xml), value, "root", errors)
                self.assertEqual(errors, [])
                check_vectors.compare(ElementTree.fromstring("<wrong/>"), value, "root", errors)
                if value != (0, 0):
                    self.assertTrue(errors)

    def test_unsupported_value_and_wrong_shapes_are_detected(self):
        for value in (None, (1,), ["a"], {"a": 1}, ("a", 1)):
            with self.subTest(value=value):
                errors = []
                check_vectors.compare(ElementTree.fromstring("<x/>"), value, "root", errors)
                self.assertTrue(errors)


class IndependentDecoderTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "corpus"
        source = (
            Path(__file__).resolve().parents[2]
            / "vanetza/asn1/tests/reference_vectors/intersection_01"
        )
        shutil.copytree(source, self.directory)

    def run_checker(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return check_vectors.main([str(self.directory)])

    def test_complete_corpus_passes(self):
        self.assertEqual(self.run_checker(), 0)

    def test_changed_uper_is_detected(self):
        path = self.directory / "srem_tram_request.uper"
        data = bytearray(path.read_bytes())
        data[0] ^= 1
        path.write_bytes(data)
        self.assertEqual(self.run_checker(), 1)

    def test_changed_xer_is_detected(self):
        path = self.directory / "srem_tram_request.xer"
        data = path.read_text(encoding="utf-8")
        self.assertIn("<stationID>20</stationID>", data)
        path.write_text(
            data.replace("<stationID>20</stationID>", "<stationID>21</stationID>"), encoding="utf-8"
        )
        self.assertEqual(self.run_checker(), 1)

    def test_wrong_size_is_detected(self):
        path = self.directory / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest[0]["bytes"] += 1
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(self.run_checker(), 1)

    def test_missing_file_is_detected(self):
        (self.directory / "mapem.uper").unlink()
        self.assertEqual(self.run_checker(), 1)

    def test_empty_manifest_cannot_pass(self):
        (self.directory / "manifest.json").write_text("[]", encoding="utf-8")
        self.assertEqual(self.run_checker(), 2)


if __name__ == "__main__":
    unittest.main()
