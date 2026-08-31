import unittest

from sshaudit.vendor import miniyaml


class ScalarTests(unittest.TestCase):
    def test_types(self):
        data = miniyaml.load(
            "a: 1\n"
            "b: -2\n"
            "c: 3.5\n"
            "d: true\n"
            "e: False\n"
            "f: null\n"
            "g: ~\n"
            "h:\n"
            "i: plain text\n"
        )
        self.assertEqual(data["a"], 1)
        self.assertEqual(data["b"], -2)
        self.assertEqual(data["c"], 3.5)
        self.assertIs(data["d"], True)
        self.assertIs(data["e"], False)
        self.assertIsNone(data["f"])
        self.assertIsNone(data["g"])
        self.assertIsNone(data["h"])
        self.assertEqual(data["i"], "plain text")

    def test_quotes_keep_strings(self):
        data = miniyaml.load('a: "1"\nb: \'true\'\nc: "line\\nbreak"\n')
        self.assertEqual(data["a"], "1")
        self.assertEqual(data["b"], "true")
        self.assertEqual(data["c"], "line\nbreak")

    def test_inline_comment_and_hash_in_value(self):
        data = miniyaml.load(
            "ref: data/binaries.yml#sudo   # points at the sudo section\n"
            "url: https://x/y#frag\n"
        )
        self.assertEqual(data["ref"], "data/binaries.yml#sudo")
        self.assertEqual(data["url"], "https://x/y#frag")


class StructureTests(unittest.TestCase):
    def test_nested_mapping_and_sequence(self):
        data = miniyaml.load(
            "defaults:\n"
            "  user: audit\n"
            "  port: 22\n"
            "hosts:\n"
            "  - alias: a\n"
            "    tags: [prod, web]\n"
            "  - alias: b\n"
            "    nested:\n"
            "      deep: yes-ish\n"
        )
        self.assertEqual(data["defaults"], {"user": "audit", "port": 22})
        self.assertEqual(data["hosts"][0]["alias"], "a")
        self.assertEqual(data["hosts"][0]["tags"], ["prod", "web"])
        self.assertEqual(data["hosts"][1]["nested"], {"deep": "yes-ish"})

    def test_flow_map_and_seq(self):
        data = miniyaml.load("a: {x: 1, y: two}\nb: [1, 2, 3]\nc: []\nd: {}\n")
        self.assertEqual(data["a"], {"x": 1, "y": "two"})
        self.assertEqual(data["b"], [1, 2, 3])
        self.assertEqual(data["c"], [])
        self.assertEqual(data["d"], {})

    def test_list_of_scalars(self):
        data = miniyaml.load("items:\n  - one\n  - two\n  - 3\n")
        self.assertEqual(data["items"], ["one", "two", 3])

    def test_document_marker_ignored(self):
        data = miniyaml.load("---\na: 1\n...\n")
        self.assertEqual(data, {"a": 1})


class BlockScalarTests(unittest.TestCase):
    def test_literal_block(self):
        data = miniyaml.load(
            "remediation: |\n"
            "  line one\n"
            "  line two\n"
            "next: 1\n"
        )
        self.assertEqual(data["remediation"], "line one\nline two\n")
        self.assertEqual(data["next"], 1)

    def test_literal_strip(self):
        data = miniyaml.load("x: |-\n  a\n  b\n")
        self.assertEqual(data["x"], "a\nb")

    def test_folded_block(self):
        data = miniyaml.load("x: >\n  a\n  b\n\n  c\n")
        self.assertEqual(data["x"], "a b\nc\n")

    def test_indentation_preserved_inside_block(self):
        data = miniyaml.load(
            "steps: |\n"
            "  1. do a\n"
            "     - detail\n"
            "  2. do b\n"
        )
        self.assertEqual(data["steps"], "1. do a\n   - detail\n2. do b\n")


class ErrorTests(unittest.TestCase):
    def test_tab_indent_rejected(self):
        with self.assertRaises(miniyaml.YAMLError):
            miniyaml.load("a:\n\tb: 1\n")

    def test_anchor_rejected(self):
        with self.assertRaises(miniyaml.YAMLError):
            miniyaml.load("a: &anchor 1\n")

    def test_alias_rejected(self):
        with self.assertRaises(miniyaml.YAMLError):
            miniyaml.load("a: *anchor\n")

    def test_tag_rejected(self):
        with self.assertRaises(miniyaml.YAMLError):
            miniyaml.load("a: !!python/object x\n")

    def test_duplicate_key_rejected(self):
        with self.assertRaises(miniyaml.YAMLError):
            miniyaml.load("a: 1\na: 2\n")

    def test_empty_document(self):
        self.assertEqual(miniyaml.load(""), {})
        self.assertEqual(miniyaml.load("\n\n# only a comment\n"), {})


if __name__ == "__main__":
    unittest.main()
