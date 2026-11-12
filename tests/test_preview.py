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
"""Unit tests for the controlled ruleset preview entry point."""
import tempfile
import unittest
from pathlib import Path

from plyara.preview import IncludeIssueKind, preview_rules


def write_rule(path, name, includes=(), imports=()):
    """Write a minimal YARA file with the given includes/imports and one rule."""
    lines = [f'import "{module}"' for module in imports]
    lines += [f'include "{target}"' for target in includes]
    lines.append(f'rule {name} {{ condition: true }}')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


class TestPreviewRules(unittest.TestCase):
    """Check controlled include resolution and rule provenance."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / 'ruleset'
        self.root.mkdir()
        self.outside = self.base / 'outside'
        self.outside.mkdir()
        write_rule(self.outside / 'secret.yar', 'SecretRule')

    def preview(self, entry='main.yar'):
        return preview_rules(self.root, entry)

    def test_relative_and_shared_includes(self):
        write_rule(self.root / 'main.yar', 'MainRule',
                   includes=('sub/a.yar', 'shared/common.yar'), imports=('pe',))
        write_rule(self.root / 'sub' / 'a.yar', 'ARule', includes=('../shared/common.yar',))
        write_rule(self.root / 'shared' / 'common.yar', 'CommonRule')

        preview = self.preview()

        self.assertEqual(preview.issues, [])
        self.assertEqual({rule['rule_name'] for rule in preview.rules},
                         {'MainRule', 'ARule', 'CommonRule'})
        # Every rule traces back to a source file inside the root
        sources = {rule['source_file'] for rule in preview.rules}
        self.assertEqual(sources, {'main.yar', 'sub/a.yar', 'shared/common.yar'})
        for rule in preview.rules:
            self.assertTrue((self.root / rule['source_file']).is_file())
        # Shared include parsed only once
        self.assertEqual(len(preview.files), 3)
        for opened in preview.files:
            self.assertTrue(opened.is_relative_to(self.root))
        # import kept as declaration only
        self.assertEqual(preview.imports, ['pe'])

    def test_external_include_not_opened(self):
        write_rule(self.root / 'main.yar', 'MainRule', includes=('../outside/secret.yar',))

        preview = self.preview()

        self.assertEqual([issue.kind for issue in preview.issues], [IncludeIssueKind.EXTERNAL])
        issue = preview.issues[0]
        self.assertEqual(issue.chain, ['main.yar'])
        self.assertEqual(issue.include, '../outside/secret.yar')
        self.assertEqual([rule['rule_name'] for rule in preview.rules], ['MainRule'])
        self.assertEqual(preview.files, [self.root / 'main.yar'])

    def test_absolute_external_include_not_opened(self):
        target = self.outside / 'secret.yar'
        write_rule(self.root / 'main.yar', 'MainRule', includes=(str(target),))

        preview = self.preview()

        self.assertEqual([issue.kind for issue in preview.issues], [IncludeIssueKind.EXTERNAL])
        self.assertNotIn('SecretRule', [rule['rule_name'] for rule in preview.rules])
        self.assertNotIn(target, preview.files)

    def test_symlink_escape_not_opened(self):
        write_rule(self.root / 'main.yar', 'MainRule', includes=('links/escape.yar',))
        link_dir = self.root / 'links'
        link_dir.mkdir()
        (link_dir / 'escape.yar').symlink_to(self.outside / 'secret.yar')

        preview = self.preview()

        self.assertEqual([issue.kind for issue in preview.issues], [IncludeIssueKind.SYMLINK_ESCAPE])
        self.assertEqual(preview.issues[0].chain, ['main.yar'])
        self.assertNotIn('SecretRule', [rule['rule_name'] for rule in preview.rules])
        self.assertEqual(preview.files, [self.root / 'main.yar'])

    def test_cycle_reports_chain(self):
        write_rule(self.root / 'main.yar', 'MainRule', includes=('a.yar',))
        write_rule(self.root / 'a.yar', 'ARule', includes=('b.yar',))
        write_rule(self.root / 'b.yar', 'BRule', includes=('a.yar',))

        preview = self.preview()

        self.assertEqual([issue.kind for issue in preview.issues], [IncludeIssueKind.CYCLE])
        self.assertEqual(preview.issues[0].chain, ['main.yar', 'a.yar', 'b.yar', 'a.yar'])
        self.assertEqual({rule['rule_name'] for rule in preview.rules},
                         {'MainRule', 'ARule', 'BRule'})

    def test_missing_include_reports_chain(self):
        write_rule(self.root / 'main.yar', 'MainRule', includes=('sub/a.yar',))
        write_rule(self.root / 'sub' / 'a.yar', 'ARule', includes=('nope.yar',))

        preview = self.preview()

        self.assertEqual([issue.kind for issue in preview.issues], [IncludeIssueKind.MISSING])
        self.assertEqual(preview.issues[0].chain, ['main.yar', 'sub/a.yar'])
        self.assertEqual(preview.issues[0].include, 'nope.yar')

    def test_entry_outside_root_rejected(self):
        with self.assertRaises(ValueError):
            preview_rules(self.root, self.outside / 'secret.yar')

    def test_missing_entry_rejected(self):
        with self.assertRaises(FileNotFoundError):
            preview_rules(self.root, 'ghost.yar')


if __name__ == '__main__':
    unittest.main()
