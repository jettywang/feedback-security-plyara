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
"""Controlled preview of YARA rulesets with include resolution.

This module provides a restricted parsing entry point for callers (such as
rule review services) that want to preview the include graph and the rules
affected by it. The caller supplies an allowed root directory and a starting
file; only files resolving inside that root are ever opened. Includes
escaping the root (directly or via symlinks), cycles, and missing files are
reported as issues carrying the include reference chain. ``import``
statements are YARA module declarations, not files, and are preserved as
declarations only.
"""
import enum
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from plyara.core import Plyara
from plyara.exceptions import ParseError

# Initialize the logger
logger = logging.getLogger(__name__)


class IncludeIssueKind(enum.Enum):
    """Categories of include resolution problems."""

    EXTERNAL = 'external'
    SYMLINK_ESCAPE = 'symlink_escape'
    CYCLE = 'cycle'
    MISSING = 'missing'
    PARSE_ERROR = 'parse_error'


@dataclass
class IncludeIssue:
    """A single include resolution problem with its reference chain.

    Attributes:
        kind: The IncludeIssueKind categorizing the problem.
        chain: Ordered include chain from the entry file to the file
            containing the offending include, as root-relative POSIX paths.
            For cycles, the repeated file closing the loop is appended last.
        include: The raw include target string as written in the source.
        message: Human readable description of the problem.
    """

    kind: IncludeIssueKind
    chain: list
    include: str
    message: str = ''


@dataclass
class RulesetPreview:
    """Result of a controlled ruleset preview.

    Attributes:
        root: Resolved allowed root directory.
        entry: Resolved entry file.
        files: Resolved paths of every file actually opened, in visit order.
        rules: Parsed rule dictionaries, each annotated with 'source_file'
            (root-relative POSIX path of the file it was parsed from).
        imports: Sorted YARA module names declared via import statements.
        issues: List of IncludeIssue objects encountered during resolution.
    """

    root: Path
    entry: Path
    files: list = field(default_factory=list)
    rules: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    issues: list = field(default_factory=list)


def preview_rules(root, entry, **parser_kwargs):
    """Parse a YARA entry file and its includes, confined to an allowed root.

    Includes are resolved relative to the including file's directory (or as
    absolute paths) and are only followed when the fully resolved path stays
    inside the allowed root. Files shared by multiple includers are parsed
    once. Import statements are kept as declarations and never resolved to
    files.

    Args:
        root: Directory the caller allows reading from.
        entry: Starting YARA file, absolute or relative to root.
        parser_kwargs: Keyword arguments forwarded to the Plyara parser.

    Returns:
        RulesetPreview: The parsed rules, opened files, declared imports,
            and any include issues (each with its reference chain).

    Raises:
        ValueError: If the entry file resolves outside the allowed root.
        FileNotFoundError: If the entry file does not exist.
    """
    root_path = Path(root).resolve()
    entry_path = Path(entry)
    if not entry_path.is_absolute():
        entry_path = root_path / entry_path
    entry_path = Path(os.path.normpath(entry_path)).resolve()

    if not entry_path.is_relative_to(root_path):
        raise ValueError(f'Entry file {entry_path} is outside allowed root {root_path}')
    if not entry_path.is_file():
        raise FileNotFoundError(f'Entry file {entry_path} does not exist')

    preview = RulesetPreview(root=root_path, entry=entry_path)
    declared_imports = set()
    completed = set()

    def relative_chain(chain):
        return [path.relative_to(root_path).as_posix() for path in chain]

    def visit(file_path, chain):
        chain = chain + [file_path]
        logger.debug('Preview opening: %s', file_path)
        preview.files.append(file_path)

        parser = Plyara(**parser_kwargs)
        try:
            rules = parser.parse_string(file_path.read_text(encoding='utf-8'))
        except ParseError as exc:
            preview.issues.append(IncludeIssue(
                kind=IncludeIssueKind.PARSE_ERROR,
                chain=relative_chain(chain),
                include='',
                message=str(exc),
            ))
            completed.add(file_path)
            return

        source_file = file_path.relative_to(root_path).as_posix()
        for rule in rules:
            rule['source_file'] = source_file
            preview.rules.append(rule)
        declared_imports.update(parser.imports)
        completed.add(file_path)

        for include in parser.includes:
            target = Path(include)
            lexical = Path(os.path.normpath(target if target.is_absolute() else file_path.parent / target))

            if not lexical.is_relative_to(root_path):
                preview.issues.append(IncludeIssue(
                    kind=IncludeIssueKind.EXTERNAL,
                    chain=relative_chain(chain),
                    include=include,
                    message=f'Include {include!r} points outside the allowed root',
                ))
                continue

            resolved = lexical.resolve()
            if not resolved.is_relative_to(root_path):
                preview.issues.append(IncludeIssue(
                    kind=IncludeIssueKind.SYMLINK_ESCAPE,
                    chain=relative_chain(chain),
                    include=include,
                    message=f'Include {include!r} resolves outside the allowed root via a symbolic link',
                ))
                continue

            if not resolved.is_file():
                preview.issues.append(IncludeIssue(
                    kind=IncludeIssueKind.MISSING,
                    chain=relative_chain(chain),
                    include=include,
                    message=f'Include {include!r} does not exist',
                ))
                continue

            if resolved in chain:
                preview.issues.append(IncludeIssue(
                    kind=IncludeIssueKind.CYCLE,
                    chain=relative_chain(chain + [resolved]),
                    include=include,
                    message=f'Include {include!r} forms a cycle',
                ))
                continue

            if resolved in completed:
                continue

            visit(resolved, chain)

    visit(entry_path, [])
    preview.imports = sorted(declared_imports)
    return preview
