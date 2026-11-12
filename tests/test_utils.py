# Copyright 2014 Christian Buia
# Copyright 2025 plyara Maintainers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Unit tests for plyara utility functions."""
import importlib.resources
import unittest

import plyara.core
from plyara.utils import generate_hash
from plyara.utils import migrate_hash
from plyara.utils import rebuild_yara_rule


class TestUtilities(unittest.TestCase):
    """Check the various utility functions."""

    def setUp(self):
        """Prepare for utility unit testing."""
        self.parser = plyara.core.Plyara()
        self.data = importlib.resources.files('tests.data.utils')
        self.imports = importlib.resources.files('tests.data.imports')
        self.common = importlib.resources.files('tests.data.common')
        # self.maxDiff = None

    def test_generate_hash(self):
        input_string = self.data.joinpath('logic_collision_ruleset.yar').read_text()

        result = plyara.core.Plyara().parse_string(input_string)

        rule_mapping = {}

        for entry in result:
            rulename = entry['rule_name']
            setname, _ = rulename.split('_')
            rulehash = generate_hash(entry)

            if setname not in rule_mapping:
                rule_mapping[setname] = [rulehash]
            else:
                rule_mapping[setname].append(rulehash)

        for setname, hashvalues in rule_mapping.items():
            self.assertTrue(len(set(hashvalues)) == 1, 'Collision detection failure for {}'.format(setname))

    def test_generate_hash_output_legacy(self):
        rule_hashes = self.data.joinpath('rulehashes_legacy.txt').read_text().splitlines()
        # Rules containing "(1..#)" or similar iterators cause Unhandled String Count Condition errors
        input_string = self.common.joinpath('test_rules_from_yara_project.yar').read_text()

        results = plyara.core.Plyara().parse_string(input_string)

        for index, result in enumerate(results):
            rulehash = generate_hash(result, legacy=True)
            self.assertEqual(rulehash, rule_hashes[index])

    def test_generate_hash_output_v1(self):
        rule_hashes = self.data.joinpath('rulehashes.txt').read_text().splitlines()
        input_string = self.common.joinpath('test_rules_from_yara_project.yar').read_text()

        results = plyara.core.Plyara().parse_string(input_string)

        for index, result in enumerate(results):
            rulehash = generate_hash(result, version='v1')
            self.assertEqual(rulehash, rule_hashes[index])

    def test_generate_hash_output_v2(self):
        rule_hashes = self.data.joinpath('rulehashes_v2.txt').read_text().splitlines()
        input_string = self.common.joinpath('test_rules_from_yara_project.yar').read_text()

        results = plyara.core.Plyara().parse_string(input_string)

        for index, result in enumerate(results):
            rulehash = generate_hash(result)
            self.assertEqual(rulehash, rule_hashes[index])

    def test_generate_hash_equivalence_boundaries(self):
        ruleset = '''
rule comments_a {
    strings:
        $foo = "abc"
    condition:
        $foo
}

rule comments_b {
    strings:
        /* review note */
        $bar = "abc" // review note
    condition:
        /* review note */
        $bar
}

rule reference_a {
    strings:
        $foo = "abc"
    condition:
        #foo == 1 and @foo > 0 and !foo > 0
}

rule reference_b {
    strings:
        $bar = "abc"
    condition:
        #bar == 1 and @bar > 0 and !bar > 0
}

rule wildcard_a {
    strings:
        $foo1 = "abc"
        $foo2 = "def"
    condition:
        any of ($foo*) and #foo* == 2 and @foo* > 0 and !foo* > 0
}

rule wildcard_b {
    strings:
        $bar1 = "abc"
        $bar2 = "def"
    condition:
        any of ($bar*) and #bar* == 2 and @bar* > 0 and !bar* > 0
}

rule wildcard_set_a {
    strings:
        $foo1 = "abc"
        $foo2 = "def"
    condition:
        any of $foo*
}

rule wildcard_set_b {
    strings:
        $bar1 = "abc"
        $bar2 = "def"
    condition:
        any of ($bar*)
}

rule count_wildcard_a {
    strings:
        $foo1 = "abc"
        $foo2 = "def"
    condition:
        #* == 2
}

rule count_wildcard_b {
    strings:
        $bar1 = "abc"
        $bar2 = "def"
    condition:
        #* == 2
}

rule set_a {
    strings:
        $a = "abc"
        $b = "def"
    condition:
        any of ($a, $b)
}

rule set_b {
    strings:
        $a = "abc"
        $b = "def"
    condition:
        any of ($b, $a)
}

rule allset_a {
    strings:
        $a = "abc"
        $b = "def"
    condition:
        all of them
}

rule allset_b {
    strings:
        $a = "abc"
        $b = "def"
    condition:
        all of ($*)
}

rule modifier_a {
    strings:
        $a = "abc" nocase
    condition:
        $a
}

rule modifier_order_a {
    strings:
        $a = "abc" wide ascii
    condition:
        $a
}

rule modifier_order_b {
    strings:
        $b = "abc" ascii wide
    condition:
        $b
}

rule modifier_b {
    strings:
        $b = "abc"
    condition:
        $b
}

rule order_a {
    strings:
        $a = "abc"
        $b = "def"
    condition:
        $a and $b
}

rule order_b {
    strings:
        $b = "def"
        $a = "abc"
    condition:
        $a and $b
}

rule condition_order_a {
    strings:
        $a = "abc"
        $b = "def"
    condition:
        $a and $b
}

rule condition_order_b {
    strings:
        $a = "abc"
        $b = "def"
    condition:
        $b and $a
}

rule logic_a {
    strings:
        $a = "abc"
        $b = "def"
    condition:
        any of ($a, $b)
}

rule logic_b {
    strings:
        $a = "abc"
        $b = "def"
    condition:
        all of ($a, $b)
}

rule byte_a {
    strings:
        $a = { 01 ~02 }
    condition:
        $a
}

rule byte_b {
    strings:
        $a = { 01 02 }
    condition:
        $a
}
'''
        rules = {entry['rule_name']: entry for entry in plyara.core.Plyara().parse_string(ruleset)}
        equivalent_pairs = [
            ('comments_a', 'comments_b'),
            ('reference_a', 'reference_b'),
            ('wildcard_a', 'wildcard_b'),
            ('wildcard_set_a', 'wildcard_set_b'),
            ('count_wildcard_a', 'count_wildcard_b'),
            ('set_a', 'set_b'),
            ('allset_a', 'allset_b'),
            ('modifier_order_a', 'modifier_order_b'),
            ('order_a', 'order_b'),
        ]
        changed_pairs = [
            ('modifier_a', 'modifier_b'),
            ('condition_order_a', 'condition_order_b'),
            ('logic_a', 'logic_b'),
            ('byte_a', 'byte_b'),
        ]

        for first, second in equivalent_pairs:
            self.assertEqual(
                generate_hash(rules[first]),
                generate_hash(rules[second]),
                'expected equivalent fingerprints for {} and {}'.format(first, second)
            )

        for first, second in changed_pairs:
            self.assertNotEqual(
                generate_hash(rules[first]),
                generate_hash(rules[second]),
                'expected distinct fingerprints for {} and {}'.format(first, second)
            )

    def test_generate_hash_rejects_unknown_version(self):
        rule = plyara.core.Plyara().parse_string('rule x { condition: true }')[0]

        with self.assertRaises(ValueError):
            generate_hash(rule, version='v3')

    def test_migrate_hash(self):
        rule = plyara.core.Plyara().parse_string('rule x { strings: $a = "abc" condition: $a }')[0]
        old_hash = generate_hash(rule, version='v1')
        current_hash = generate_hash(rule)

        migrated = migrate_hash(old_hash, rule)
        self.assertEqual('migrated', migrated['status'])
        self.assertEqual(current_hash, migrated['new_hash'])

        current = migrate_hash(current_hash, rule)
        self.assertEqual('current', current['status'])
        self.assertEqual(current_hash, current['new_hash'])

        legacy_migrated = migrate_hash(generate_hash(rule, legacy=True), rule)
        self.assertEqual('migrated', legacy_migrated['status'])
        self.assertEqual(current_hash, legacy_migrated['new_hash'])

        changed_rule = plyara.core.Plyara().parse_string(
            'rule x { strings: $a = "def" condition: $a }'
        )[0]
        review = migrate_hash(old_hash, changed_rule)
        self.assertEqual('pending_review', review['status'])
        self.assertNotIn('new_hash', review)

        missing_rule = migrate_hash(old_hash)
        self.assertEqual('pending_review', missing_rule['status'])
        self.assertNotIn('new_hash', missing_rule)

    def test_rebuild_yara_rule(self):
        input_string = self.data.joinpath('rebuild_ruleset.yar').read_text(encoding='utf-8')
        test_result = self.data.joinpath('rebuild_ruleset_good_enough.yar').read_text(encoding='utf-8')

        result = plyara.core.Plyara().parse_string(input_string)

        rebuilt_rules = str()
        for rule in result:
            rebuilt_rules += rebuild_yara_rule(rule)

        self.assertEqual(test_result, rebuilt_rules)

    def test_rebuild_yara_rule_metadata(self):
        test_rule = """
        rule check_meta {
            meta:
                string_value = "TEST STRING"
                string_value = "DIFFERENT TEST STRING"
                bool_value = true
                bool_value = false
                digit_value = 5
                digit_value = 10
            condition:
                true
        }
        """
        parsed = plyara.core.Plyara().parse_string(test_rule)
        for rule in parsed:
            unparsed = rebuild_yara_rule(rule)
            self.assertIn('string_value = "TEST STRING"', unparsed)
            self.assertIn('string_value = "DIFFERENT TEST STRING"', unparsed)
            self.assertIn('bool_value = true', unparsed)
            self.assertIn('bool_value = false', unparsed)
            self.assertIn('digit_value = 5', unparsed)
            self.assertIn('digit_value = 10', unparsed)


if __name__ == '__main__':
    unittest.main()
