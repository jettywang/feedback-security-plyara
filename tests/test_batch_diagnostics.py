"""Unit tests for plyara batch diagnostic mode."""
import unittest

import plyara.core
from plyara.exceptions import ParseTypeError

BROKEN_RULESET = r'''import "pe"

rule good_one {
    strings:
        $a = "hello"
    condition:
        $a
}

// rule comment_fake { condition: true }
/* rule block_comment_fake { condition: false } */

rule broken_regex {
    strings:
        $a = /foo\/
    condition:
        $a
}

rule broken_string {
    strings:
        $a = "unterminated
    condition:
        $a
}

rule good_two {
    condition:
        good_one and pe.number_of_sections > 0
}

rule good_three {
    condition:
        broken_regex or good_two
}
'''

CLEAN_RULESET = r'''import "elf"

rule alpha {
    strings:
        $a = "one"
    condition:
        $a
}

rule beta {
    condition:
        alpha and elf.machine == elf.EM_X86_64
}
'''

UNTERMINATED_RULESET = r'''rule good { condition: true }

rule unclosed {
    strings:
        $a = "x"
    condition:
        $a

rule never_seen { condition: false }
'''

HEADER_ONLY_RULESET = r'''rule header_only

rule good { condition: true }
'''


class TestBatchDiagnostics(unittest.TestCase):
    """Check batch diagnostic mode parsing and recovery."""

    def setUp(self):
        self.parser = plyara.core.Plyara()

    def test_recovers_rules_around_malformed_rules(self):
        """Check that rules before and after malformed rules are recovered."""
        result = self.parser.parse_string_with_diagnostics(BROKEN_RULESET)

        self.assertEqual([rule['rule_name'] for rule in result['rules']],
                         ['good_one', 'good_two', 'good_three'])

    def test_comment_rule_keywords_are_not_boundaries(self):
        """Check that rule keywords inside comments do not create fake rules or diagnostics."""
        result = self.parser.parse_string_with_diagnostics(BROKEN_RULESET)

        rule_names = [rule['rule_name'] for rule in result['rules']]
        self.assertNotIn('comment_fake', rule_names)
        self.assertNotIn('block_comment_fake', rule_names)
        self.assertEqual(len(result['diagnostics']), 2)
        self.assertNotIn('comments', result['rules'][0])

    def test_broken_regex_diagnostic(self):
        """Check the diagnostic reported for a rule with a broken regex."""
        result = self.parser.parse_string_with_diagnostics(BROKEN_RULESET)
        diagnostic = result['diagnostics'][0]

        self.assertEqual(diagnostic['rule_name'], 'broken_regex')
        self.assertEqual(diagnostic['line'], 15)
        self.assertEqual(diagnostic['skipped_start_line'], 13)
        self.assertEqual(diagnostic['skipped_end_line'], 18)
        self.assertTrue(diagnostic['recovered'])
        self.assertTrue(diagnostic['message'])

    def test_unclosed_string_diagnostic(self):
        """Check the diagnostic reported for a rule with an unclosed string."""
        result = self.parser.parse_string_with_diagnostics(BROKEN_RULESET)
        diagnostic = result['diagnostics'][1]

        self.assertEqual(diagnostic['rule_name'], 'broken_string')
        self.assertEqual(diagnostic['line'], 22)
        self.assertEqual(diagnostic['skipped_start_line'], 20)
        self.assertEqual(diagnostic['skipped_end_line'], 25)
        self.assertTrue(diagnostic['recovered'])

    def test_recovered_rule_line_numbers(self):
        """Check that recovered rules carry line numbers from the original input."""
        result = self.parser.parse_string_with_diagnostics(BROKEN_RULESET)
        lines = {rule['rule_name']: (rule['start_line'], rule['stop_line']) for rule in result['rules']}

        self.assertEqual(lines['good_one'], (3, 8))
        self.assertEqual(lines['good_two'], (27, 30))
        self.assertEqual(lines['good_three'], (32, 35))

    def test_dependencies_incomplete_flag(self):
        """Check that incomplete dependencies are flagged after rules are skipped."""
        result = self.parser.parse_string_with_diagnostics(BROKEN_RULESET)

        self.assertFalse(result['dependencies_complete'])
        rules = {rule['rule_name']: rule for rule in result['rules']}
        self.assertNotIn('dependencies_incomplete', rules['good_one'])
        self.assertNotIn('dependencies_incomplete', rules['good_two'])
        self.assertTrue(rules['good_three']['dependencies_incomplete'])

    def test_imports_applied_to_recovered_rules(self):
        """Check that file-scoped imports are applied to recovered rules."""
        result = self.parser.parse_string_with_diagnostics(BROKEN_RULESET)
        rules = {rule['rule_name']: rule for rule in result['rules']}

        self.assertNotIn('imports', rules['good_one'])
        self.assertEqual(rules['good_two']['imports'], ['pe'])

    def test_import_effects_option_propagates(self):
        """Check that the import_effects option is honored in batch diagnostic mode."""
        parser = plyara.core.Plyara(import_effects=True)
        result = parser.parse_string_with_diagnostics(BROKEN_RULESET)

        for rule in result['rules']:
            with self.subTest(rule=rule['rule_name']):
                self.assertEqual(rule['imports'], ['pe'])

    def test_unclosed_rule_body_skips_to_end(self):
        """Check that an unconfirmable boundary skips the rest of the input."""
        result = self.parser.parse_string_with_diagnostics(UNTERMINATED_RULESET)

        self.assertEqual([rule['rule_name'] for rule in result['rules']], ['good'])
        self.assertEqual(len(result['diagnostics']), 1)
        diagnostic = result['diagnostics'][0]
        self.assertEqual(diagnostic['rule_name'], 'unclosed')
        self.assertEqual(diagnostic['line'], 3)
        self.assertEqual(diagnostic['skipped_start_line'], 3)
        self.assertEqual(diagnostic['skipped_end_line'], 9)
        self.assertFalse(diagnostic['recovered'])
        self.assertFalse(result['dependencies_complete'])

    def test_rule_header_without_body_is_skipped(self):
        """Check that a rule header without a body is skipped and parsing resumes."""
        result = self.parser.parse_string_with_diagnostics(HEADER_ONLY_RULESET)

        self.assertEqual([rule['rule_name'] for rule in result['rules']], ['good'])
        self.assertEqual(result['rules'][0]['start_line'], 3)
        self.assertEqual(len(result['diagnostics']), 1)
        diagnostic = result['diagnostics'][0]
        self.assertEqual(diagnostic['rule_name'], 'header_only')
        self.assertEqual(diagnostic['line'], 1)
        self.assertTrue(diagnostic['recovered'])

    def test_clean_file_has_no_diagnostics(self):
        """Check that a clean file parses completely with no diagnostics."""
        result = self.parser.parse_string_with_diagnostics(CLEAN_RULESET)

        self.assertEqual([rule['rule_name'] for rule in result['rules']], ['alpha', 'beta'])
        self.assertEqual(result['diagnostics'], list())
        self.assertTrue(result['dependencies_complete'])
        self.assertEqual(result['rules'][1]['imports'], ['elf'])

    def test_no_residual_state_between_files(self):
        """Check that consecutive batch parses and strict parses keep no residual state."""
        first = self.parser.parse_string_with_diagnostics(BROKEN_RULESET)
        second = self.parser.parse_string_with_diagnostics(CLEAN_RULESET)

        self.assertEqual(len(first['diagnostics']), 2)
        self.assertEqual(second['diagnostics'], list())
        self.assertTrue(second['dependencies_complete'])
        self.assertEqual([rule['rule_name'] for rule in second['rules']], ['alpha', 'beta'])
        self.assertEqual(self.parser.rules, list())

        strict = self.parser.parse_string(CLEAN_RULESET)
        self.assertEqual([rule['rule_name'] for rule in strict], ['alpha', 'beta'])

    def test_trailing_comment_on_closing_line(self):
        """Check that a comment on the closing brace line attaches to the rule, not a boundary."""
        input_string = 'rule a { condition: true } // rule fake { condition: true }\nrule b { condition: false }'
        result = self.parser.parse_string_with_diagnostics(input_string)

        self.assertEqual([rule['rule_name'] for rule in result['rules']], ['a', 'b'])
        self.assertEqual(result['diagnostics'], list())
        self.assertEqual(result['rules'][0]['comments'], ['// rule fake { condition: true }'])

    def test_crlf_line_numbers_are_visual(self):
        """Check that CRLF input yields consistent visual line numbers."""
        input_string = ('rule a {\r\n    strings:\r\n        $a = "x\r\n    condition:\r\n'
                        '        $a\r\n}\r\n\r\nrule b { condition: true }\r\n')
        result = self.parser.parse_string_with_diagnostics(input_string)

        self.assertEqual([rule['rule_name'] for rule in result['rules']], ['b'])
        diagnostic = result['diagnostics'][0]
        self.assertEqual(diagnostic['rule_name'], 'a')
        self.assertEqual(diagnostic['line'], 3)
        self.assertEqual(diagnostic['skipped_start_line'], 1)
        self.assertEqual(diagnostic['skipped_end_line'], 6)
        self.assertEqual(result['rules'][0]['start_line'], 8)

    def test_strict_parse_entry_unchanged(self):
        """Check that the strict parse entry still raises on the malformed ruleset."""
        with self.assertRaises(ParseTypeError):
            self.parser.parse_string(BROKEN_RULESET)


if __name__ == '__main__':
    unittest.main()
