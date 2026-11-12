"""Round-trip tests for parse -> modify -> rebuild -> re-parse workflows.

Simulates a rule-management backend that parses YARA rules with plyara,
edits tags/metadata/strings on the parsed dictionary, and rebuilds the
rule text with plyara.utils.rebuild_yara_rule.  The rebuilt text is
parsed again and compared against handwritten expectations covering
string content, scopes, modifiers, and condition terms.
"""
import unittest

import plyara.core
from plyara.utils import rebuild_yara_rule


def semantic(rule):
    """Keep only detection-relevant keys (drop line numbers and raw sections)."""
    return {key: value for key, value in rule.items()
            if key not in ('start_line', 'stop_line') and not key.startswith('raw_')}


class TestRebuildRoundTrip(unittest.TestCase):
    """Check that rebuilt rules re-parse to the same detection content."""

    def parse_one(self, text):
        """Parse text that must contain exactly one rule."""
        rules = plyara.core.Plyara().parse_string(text)
        self.assertEqual(len(rules), 1)
        return rules[0]

    def roundtrip(self, rule):
        """Rebuild one rule and re-parse it; exactly one rule must come back."""
        rebuilt = rebuild_yara_rule(rule)
        rules = plyara.core.Plyara().parse_string(rebuilt)
        self.assertEqual(len(rules), 1, 'rebuild must yield exactly the original rule')
        return rebuilt, rules[0]

    def test_modify_tags_preserves_rule(self):
        sample = r'''
private rule quote_backslash : old_tag
{
    strings:
        $q = "hark, a \"quoted\" string" fullword ascii
        $p = "C:\\Windows\\System32" nocase
        $r = /state: (on|off)\/end/is wide
        $h = { 6A 40 [4-6] 68 00 [4-] 90 }
    condition:
        any of them and uint16(0) == 0x5A4D
}
'''
        expected_strings = [
            {'name': '$q', 'value': r'hark, a \"quoted\" string', 'type': 'text',
             'modifiers': ['fullword', 'ascii']},
            {'name': '$p', 'value': r'C:\\Windows\\System32', 'type': 'text',
             'modifiers': ['nocase']},
            {'name': '$r', 'value': r'/state: (on|off)\/end/is', 'type': 'regex',
             'modifiers': ['wide']},
            {'name': '$h', 'value': r'{ 6A 40 [4-6] 68 00 [4-] 90 }', 'type': 'byte'},
        ]
        expected_condition = ['any', 'of', 'them', 'and', 'uint16', '(', '0', ')', '==', '0x5A4D']

        rule = self.parse_one(sample)
        rule['tags'] = ['new_tag']

        rebuilt, again = self.roundtrip(rule)

        self.assertNotIn('old_tag', rebuilt)
        self.assertIn(r'$q = "hark, a \"quoted\" string" fullword ascii', rebuilt)
        self.assertEqual(again['rule_name'], 'quote_backslash')
        self.assertEqual(again['scopes'], ['private'])
        self.assertEqual(again['tags'], ['new_tag'])
        self.assertEqual(again['strings'], expected_strings)
        self.assertEqual(again['condition_terms'], expected_condition)

    def test_modify_metadata_preserves_rule(self):
        sample = r'''
rule meta_case
{
    meta:
        author = "analyst"
        motto = "say \"hi\" \\ then go"
        version = 1
        active = false
    strings:
        $a = "trigger"
    condition:
        $a
}
'''
        rule = self.parse_one(sample)
        rule['metadata'][0] = {'author': 'hunter'}
        rule['metadata'][2] = {'version': 2}
        rule['metadata'][3] = {'active': True}

        rebuilt, again = self.roundtrip(rule)

        self.assertIn(r'motto = "say \"hi\" \\ then go"', rebuilt)
        self.assertEqual(again['metadata'], [
            {'author': 'hunter'},
            {'motto': r'say \"hi\" \\ then go'},
            {'version': 2},
            {'active': True},
        ])
        self.assertEqual(again['strings'], [{'name': '$a', 'value': 'trigger', 'type': 'text'}])
        self.assertEqual(again['condition_terms'], ['$a'])

    def test_modify_plain_string_preserves_rule(self):
        sample = r'''
rule string_case
{
    strings:
        $keep = "do not \\ touch \"me\""
        $change = "old_value"
    condition:
        all of them
}
'''
        rule = self.parse_one(sample)
        for entry in rule['strings']:
            if entry['name'] == '$change':
                entry['value'] = r'new \"value\" \\ path'

        rebuilt, again = self.roundtrip(rule)

        self.assertIn(r'$change = "new \"value\" \\ path"', rebuilt)
        self.assertEqual(again['strings'], [
            {'name': '$keep', 'value': r'do not \\ touch \"me\"', 'type': 'text'},
            {'name': '$change', 'value': r'new \"value\" \\ path', 'type': 'text'},
        ])
        self.assertEqual(again['condition_terms'], ['all', 'of', 'them'])

    def test_rebuild_keeps_only_original_rules(self):
        sample = r'''
rule first : keepme
{
    strings:
        $a = "one"
    condition:
        $a
}
rule second
{
    strings:
        $b = { 01 02 [3-] 03 }
    condition:
        all of them
}
'''
        rules = plyara.core.Plyara().parse_string(sample)
        self.assertEqual(len(rules), 2)

        rules[0]['tags'] = ['retagged']
        rebuilt = ''.join(rebuild_yara_rule(rule) for rule in rules)
        again = plyara.core.Plyara().parse_string(rebuilt)

        self.assertEqual(len(again), 2, 'rebuild must not create or drop rules')
        self.assertEqual([rule['rule_name'] for rule in again], ['first', 'second'])
        self.assertEqual(again[0]['tags'], ['retagged'])
        self.assertEqual(again[0]['condition_terms'], ['$a'])
        self.assertEqual(semantic(again[1]), semantic(rules[1]))

    def test_lookalike_strings_keep_distinct_meanings(self):
        cases = [
            # escaped backslash (literal "\") vs newline escape
            (r'$a = "a\\b"', {'name': '$a', 'value': r'a\\b', 'type': 'text'}),
            (r'$a = "a\nb"', {'name': '$a', 'value': r'a\nb', 'type': 'text'}),
            # escaped slash inside a regex vs plain text with a slash
            (r'$a = /a\/b/', {'name': '$a', 'value': r'/a\/b/', 'type': 'regex'}),
            (r'$a = "a/b"', {'name': '$a', 'value': 'a/b', 'type': 'text'}),
            # open-ended vs bounded vs unbounded hex jumps
            (r'$a = { 01 [4-] 02 }', {'name': '$a', 'value': '{ 01 [4-] 02 }', 'type': 'byte'}),
            (r'$a = { 01 [4-6] 02 }', {'name': '$a', 'value': '{ 01 [4-6] 02 }', 'type': 'byte'}),
            (r'$a = { 01 [-] 02 }', {'name': '$a', 'value': '{ 01 [-] 02 }', 'type': 'byte'}),
            # bare xor vs ranged xor
            (r'$a = "x" xor', {'name': '$a', 'value': 'x', 'type': 'text', 'modifiers': ['xor']}),
            (r'$a = "x" xor(0x01-0x1f)', {'name': '$a', 'value': 'x', 'type': 'text',
                                          'modifiers': ['xor(0x01-0x1f)']}),
            # regex trailing modifiers vs the nocase string modifier
            (r'$a = /foo/i', {'name': '$a', 'value': '/foo/i', 'type': 'regex'}),
            (r'$a = /foo/s', {'name': '$a', 'value': '/foo/s', 'type': 'regex'}),
            (r'$a = /foo/ nocase', {'name': '$a', 'value': '/foo/', 'type': 'regex',
                                    'modifiers': ['nocase']}),
        ]
        parsed_entries = []
        for declaration, expected in cases:
            with self.subTest(declaration=declaration):
                sample = 'rule lookalike\n{{\n    strings:\n        {}\n    condition:\n        $a\n}}\n'.format(
                    declaration)
                rule = self.parse_one(sample)
                self.assertEqual(rule['strings'], [expected])

                _, again = self.roundtrip(rule)
                self.assertEqual(again['strings'], [expected])
                self.assertEqual(again['condition_terms'], ['$a'])
                parsed_entries.append(rule['strings'][0])

        # no two look-alike samples may collapse into the same parsed entry
        self.assertEqual(len({repr(entry) for entry in parsed_entries}), len(cases))

    def test_lookalike_scopes_keep_distinct_meanings(self):
        cases = [
            ('rule scoped', []),
            ('private rule scoped', ['private']),
            ('global rule scoped', ['global']),
            ('private global rule scoped', ['private', 'global']),
        ]
        parsed_scopes = []
        for header, expected_scopes in cases:
            with self.subTest(header=header):
                sample = '{}\n{{\n    condition:\n        true\n}}\n'.format(header)
                rule = self.parse_one(sample)
                self.assertEqual(rule.get('scopes', []), expected_scopes)

                rebuilt, again = self.roundtrip(rule)
                if expected_scopes:
                    self.assertIn(header, rebuilt)
                self.assertEqual(again.get('scopes', []), expected_scopes)
                self.assertEqual(again['condition_terms'], ['true'])
                parsed_scopes.append(tuple(expected_scopes))

        self.assertEqual(len(set(parsed_scopes)), len(cases))


if __name__ == '__main__':
    unittest.main()
