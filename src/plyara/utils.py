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
"""plyara utility functions.

This module contains various utility functions for working with plyara output.
"""
import hashlib
import logging
import re
import warnings

from plyara.core import Parser

# Initialize the logger
logger = logging.getLogger(__name__)


def is_valid_rule_name(entry):
    """Check to see if entry is a valid rule name.

    Args:
        entry: String containing rule name.

    Returns:
        bool
    """
    warnings.warn(
        'Rule name validity checked by parser. is_valid_rule_name will be removed in plyara version 2.3.0',
        DeprecationWarning
    )
    # Check if entry is blank
    if not entry:
        return False

    # Check length
    if len(entry) > 128:
        return False

    # Ensure doesn't start with a digit
    if entry[0].isdigit():
        return False

    # Accept only alphanumeric and underscores
    if not re.match(r'[a-zA-Z_][a-zA-Z_0-9]*$', entry):
        return False

    # Verify not in keywords
    if entry in Parser.KEYWORDS:
        return False

    return True


def is_valid_rule_tag(entry):
    """Check to see if entry is a valid rule tag.

    Args:
        entry: String containing tag.

    Returns:
        bool
    """
    warnings.warn(
        'Tag name validity checked by parser. is_valid_rule_tag will be removed in plyara version 2.3.0',
        DeprecationWarning
    )
    # Same lexical conventions as name
    return is_valid_rule_name(entry)


def detect_imports(rule):
    """Take a parsed yararule and provide a list of required imports based on condition.

    Args:
        rule: Dict output from a parsed rule.

    Returns:
        list: Imports that are required.
    """
    warnings.warn(
        'Imports now parsed for all rules. detect_imports will be removed in plyara version 2.3.0',
        DeprecationWarning
    )
    detected_imports = list()
    condition_terms = rule['condition_terms']

    for imp in Parser.IMPORT_OPTIONS:
        imp_module = '{}.'.format(imp)

        for term in condition_terms:
            if term.startswith(imp_module):
                detected_imports.append(imp)
                break

    return detected_imports


def detect_dependencies(rule):
    """Take a parsed yararule and provide a list of external rule dependencies.

    Args:
        rule: Dict output from a parsed rule.

    Returns:
        list: External rule dependencies.
    """
    warnings.warn(
        'Deprecation: detect_dependencies will be removed in plyara version 2.3.0',
        DeprecationWarning
    )
    dependencies = list()
    string_iteration_variables = list()
    condition_terms = rule['condition_terms']

    # Number of terms for index iteration and reference
    term_count = len(condition_terms)

    for index in range(0, term_count):
        # Grab term by index
        term = condition_terms[index]

        if is_valid_rule_name(term) and (term not in Parser.IMPORT_OPTIONS):
            # Grab reference to previous term for logic checks
            if index > 0:
                previous_term = condition_terms[index - 1]
            else:
                previous_term = None

            # Grab reference to next term for logic checks
            if index < (term_count - 1):
                next_term = condition_terms[index + 1]
            else:
                next_term = None

            # Extend term indexes beyond wrapping parentheses for logic checks
            if previous_term == '(' and next_term == ')':
                if (index - 2) >= 0:
                    previous_term = condition_terms[index - 2]
                else:
                    previous_term = None

                if (index + 2) < term_count:
                    next_term = condition_terms[index + 2]
                else:
                    next_term = None

            # Check if reference is a variable for string iteration
            if term in string_iteration_variables:
                continue

            if previous_term in ('any', 'all', ) and next_term == 'in':
                string_iteration_variables.append(term)
                continue

            # Check for external string variable dependency
            if next_term in ('matches', 'contains', ) or previous_term in ('matches', 'contains', ):
                continue

            # Check for external integer variable dependency
            if next_term in Parser.COMPARISON_OPERATORS or previous_term in Parser.COMPARISON_OPERATORS:
                continue

            # Check for external boolean dependency may not be possible without stripping out valid rule references

            # Checks for likely rule reference
            if previous_term is None and next_term is None:
                dependencies.append(term)
            elif previous_term in ('and', 'or', 'not', ) or next_term in ('and', 'or', 'not', ):
                dependencies.append(term)

    return dependencies


_HASH_ALGORITHM = 'sha256'
_HASH_VERSION = 'v2'
_LEGACY_HASH_VERSION = 'v1'
_REFERENCE_TYPES = {
    '$': 'STRINGVALUE',
    '#': 'COUNTOFSTRING',
    '@': 'POSITIONOFSTRING',
    '!': 'LENGTHOFSTRING',
}


def _hash_condition(condition_mapping, version=None):
    digest = hashlib.sha256(''.join(condition_mapping).encode()).hexdigest()

    if version is None:
        return digest

    return '{}_{}_{}'.format(version, _HASH_ALGORITHM, digest)


def _canonical_string_value(entry):
    entry_type = entry['type']
    value = entry['value']

    if entry_type == 'byte':
        value = re.sub(r'/\*.*?\*/', '', value, flags=re.DOTALL)
        value = re.sub(r'//.*', '', value)
        value = re.sub(r'\s+', '', value)

    canonical_value = '{}:{}'.format(entry_type, value)
    modifiers = sorted(entry.get('modifiers', list()))

    if modifiers:
        canonical_value += '<MODIFIED>{}'.format(' & '.join(modifiers))

    return canonical_value


def _wildcard_pattern(identifier):
    pattern = [re.escape('$')]

    for character in identifier:
        if character == '*':
            pattern.append('.*')
        else:
            pattern.append(re.escape(character))

    return re.compile(''.join(pattern))


def _reference_values(reference, string_mapping, conditions):
    symbol = reference[0]
    identifier = reference[1:]
    named_strings = string_mapping['named']

    if identifier == '*':
        values = list(named_strings.values())
        values.extend(string_mapping['anonymous'])
    elif identifier.endswith('*'):
        pattern = _wildcard_pattern(identifier)
        values = [value for name, value in named_strings.items() if pattern.match(name)]
    else:
        name = '${}'.format(identifier)

        if name in named_strings:
            return named_strings[name]

        logger.error(f'Unhandled String Condition "{reference}" in "{" ".join(conditions)}"')
        return reference

    return ' | '.join(sorted(values))


def _canonical_reference(reference, string_mapping, conditions):
    if reference in ('#', '@', '!', '$') or reference[:1] not in _REFERENCE_TYPES or reference == '!=':
        return reference

    reference_type = _REFERENCE_TYPES[reference[0]]
    return '<{}>{}'.format(
        reference_type,
        _reference_values(reference, string_mapping, conditions)
    )


def _is_string_reference(term):
    return term not in ('#', '@', '!', '$') and term != '!=' and term[:1] in _REFERENCE_TYPES


def _canonical_string_set(terms, string_mapping, conditions):
    members = [
        _canonical_reference(term, string_mapping, conditions)
        for term in terms
        if term != ','
    ]
    return ['('] + sorted(members) + [')']


def _canonical_condition_terms(rule, string_mapping):
    conditions = list(rule['condition_terms'])
    canonical_terms = list()
    index = 0

    position = 0
    while position < len(conditions) - 1:
        if conditions[position] == '#' and conditions[position + 1] == '*':
            conditions[position:position + 2] = ['#*']
        position += 1

    while index < len(conditions):
        term = conditions[index]

        if term == 'them':
            values = sorted(string_mapping['named'].values())
            values.extend(string_mapping['anonymous'])
            canonical_terms.extend(['(', '<STRINGVALUE>{}'.format(' | '.join(sorted(values))), ')'])
            index += 1
        elif _is_string_reference(term) and term.endswith('*'):
            reference = _canonical_reference(term, string_mapping, conditions)
            if canonical_terms and canonical_terms[-1] == 'of':
                canonical_terms.extend(['(', reference, ')'])
            else:
                canonical_terms.append(reference)
            index += 1
        elif term == '(':
            end_index = index + 1
            depth = 1

            while end_index < len(conditions):
                if conditions[end_index] == '(':
                    depth += 1
                elif conditions[end_index] == ')':
                    depth -= 1
                    if depth == 0:
                        break
                end_index += 1

            set_terms = [
                member for member in conditions[index + 1:end_index]
                if member not in ('(', ')')
            ]

            if end_index < len(conditions) and set_terms and all(
                member == ',' or _is_string_reference(member) for member in set_terms
            ):
                canonical_terms.extend(_canonical_string_set(set_terms, string_mapping, conditions))
                index = end_index + 1
            else:
                canonical_terms.append(term)
                index += 1
        elif _is_string_reference(term):
            canonical_terms.append(_canonical_reference(term, string_mapping, conditions))
            index += 1
        else:
            canonical_terms.append(term)
            index += 1

    return canonical_terms


def _build_string_mapping(rule):
    string_mapping = {'anonymous': list(), 'named': dict()}

    for entry in rule.get('strings', list()):
        value = _canonical_string_value(entry)

        if entry['name'] == '$':
            string_mapping['anonymous'].append(value)
        else:
            string_mapping['named'][entry['name']] = value

    return string_mapping


def _legacy_string_mapping(rule):
    string_mapping = {'anonymous': list(), 'named': dict()}

    for entry in rule.get('strings', list()):
        if entry['type'] == 'byte':
            value = re.sub(r'[^-a-fA-F?0-9\[\]{}]+', '', entry['value'])
        else:
            value = entry['value']

        modifiers = entry.get('modifiers', list())
        if modifiers:
            value += '<MODIFIED>{}'.format(' & '.join(sorted(modifiers)))

        if entry['name'] == '$':
            string_mapping['anonymous'].append(value)
        else:
            string_mapping['named'][entry['name']] = value

    return string_mapping


def _legacy_condition_mapping(rule, string_mapping):
    condition_string_prefaces = ('$', '!', '#', '@')
    conditions = rule['condition_terms']
    condition_mapping = list()
    string_values = sorted(string_mapping['anonymous'] + list(string_mapping['named'].values()))

    for cond in conditions:
        if cond == 'them' or cond == '$*':
            all_values = '<STRINGVALUE>{}'.format(' | '.join(string_values))
            if cond == 'them':
                condition_mapping.extend(['(', all_values, ')'])
            else:
                condition_mapping.append(all_values)
        elif cond in ['#', '@', '!', '$']:
            condition_mapping.append(cond)
        elif cond.startswith('$') and cond != '$':
            if cond in string_mapping['named']:
                condition_mapping.append('<STRINGVALUE>{}'.format(string_mapping['named'][cond]))
            elif '*' in cond:
                wildcard_strings = list()
                wildcard_pattern = re.compile(cond.replace('$', r'\$').replace('*', '.*'))

                for name, value in string_mapping['named'].items():
                    if wildcard_pattern.match(name):
                        wildcard_strings.append(value)

                wildcard_strings.sort()
                condition_mapping.append('<STRINGVALUE>{}'.format(' | '.join(wildcard_strings)))
            else:
                logger.error(f'Unhandled String Condition "{cond}" in "{" ".join(conditions)}"')
        elif cond[:1] in condition_string_prefaces and cond not in ('#', '!='):
            symbol = cond[:1]
            named_cond = '${}'.format(cond[1:])
            symbol_type = _REFERENCE_TYPES.get(symbol, 'UNKNOWN')

            if named_cond in string_mapping['named']:
                condition_mapping.append('<{}>{}'.format(symbol_type, string_mapping['named'][named_cond]))
            else:
                condition_mapping.append('<{}>{}'.format(symbol_type, named_cond))
                logger.error(f'Unhandled {symbol_type} Condition "{symbol}" in "{" ".join(conditions)}"')
        else:
            condition_mapping.append(cond)

    return condition_mapping


def generate_hash(rule, legacy=False, version=_HASH_VERSION):
    """Calculate a secure hash of the matching logic in rule strings and condition.

    The hash excludes comments, metadata, tags, scopes, rule names, and unused strings that cannot affect the
    condition. String declaration order, modifier declaration order, and the members of an ``of`` set are
    canonicalized because those changes do not alter matching logic.

    Args:
        rule: Dict output from a parsed rule.
        legacy: Enables the original unprefixed hash output.
        version: Selects the versioned canonicalization rules.

    Returns:
        str: hexdigest
    """
    if legacy:
        string_mapping = _legacy_string_mapping(rule)
        condition_mapping = _legacy_condition_mapping(rule, string_mapping)
        return _hash_condition(condition_mapping)

    if version not in (_LEGACY_HASH_VERSION, _HASH_VERSION):
        raise ValueError('Unsupported logic hash version: {}'.format(version))

    if version == _LEGACY_HASH_VERSION:
        string_mapping = _legacy_string_mapping(rule)
        condition_mapping = _legacy_condition_mapping(rule, string_mapping)
    else:
        string_mapping = _build_string_mapping(rule)
        condition_mapping = _canonical_condition_terms(rule, string_mapping)

    return _hash_condition(condition_mapping, version)


def migrate_hash(old_hash, rule=None):
    """Migrate a stored logic hash when a current rule proves its disposition remains valid.

    A hash cannot be reversed, so a current parsed rule is required. If that rule reproduces the stored v1
    fingerprint, its v2 fingerprint is returned. Otherwise the record remains assigned to the caller's review
    queue rather than inheriting the old false-positive disposition.

    Args:
        old_hash: Previously stored logic hash, with or without the v1 prefix.
        rule: Dict output from parsing the current rule.

    Returns:
        dict: Migration status and, when equivalence is proven, the replacement hash.
    """
    result = {'old_hash': old_hash, 'status': 'pending_review'}

    if rule is None:
        result['reason'] = 'current rule required to prove equivalence'
        return result

    new_hash = generate_hash(rule)

    if old_hash == new_hash:
        result['status'] = 'current'
        result['new_hash'] = new_hash
        return result

    legacy_hash = generate_hash(rule, legacy=True)
    v1_hash = generate_hash(rule, version=_LEGACY_HASH_VERSION)

    if old_hash == legacy_hash or old_hash == v1_hash:
        result['status'] = 'migrated'
        result['new_hash'] = new_hash
    else:
        result['reason'] = 'current rule does not reproduce the stored v1 fingerprint'

    return result


def rebuild_yara_rule(rule, condition_indents=False):
    """Take a parsed yararule and rebuild it into a usable one.

    Args:
        rule: Dict output from a parsed rule.
        condition_indents: Use nested indentation for condition

    Returns:
        str: Formatted text string of YARA rule.
    """
    rule_format = "{imports}{scopes}rule {rulename}{tags}\n{{{meta}{strings}{condition}\n}}\n"

    rule_name = rule['rule_name']

    # Rule Imports
    if rule.get('imports'):
        unpacked_imports = ['import "{}"\n'.format(entry) for entry in rule['imports']]
        rule_imports = '{}\n'.format(''.join(unpacked_imports))
    else:
        rule_imports = str()

    # Rule Scopes
    if rule.get('scopes'):
        rule_scopes = '{} '.format(' '.join(rule['scopes']))
    else:
        rule_scopes = str()

    # Rule Tags
    if rule.get('tags'):
        rule_tags = ' : {}'.format(' '.join(rule['tags']))
    else:
        rule_tags = str()

    # Rule Metadata
    if rule.get('metadata'):
        unpacked_meta = []
        kv_list = [(k, ) + (v, ) for dic in rule['metadata'] for k, v in dic.items()]

        # Check for and handle correctly quoting string metadata
        for k, v in kv_list:
            if isinstance(v, bool):
                v = str(v).lower()
            elif isinstance(v, int):
                v = str(v)
            else:
                v = '"{}"'.format(v)
            unpacked_meta.append('\n\t\t{key} = {value}'.format(key=k, value=v))
        rule_meta = '\n\tmeta:{}\n'.format(''.join(unpacked_meta))
    else:
        rule_meta = str()

    # Rule Strings
    if rule.get('strings'):

        string_container = list()

        for rule_string in rule['strings']:
            if 'modifiers' in rule_string:
                string_modifiers = [x for x in rule_string['modifiers'] if isinstance(x, str)]

                if rule_string['type'] == 'text':
                    string_format = '\n\t\t{} = "{}" {}'
                else:
                    string_format = '\n\t\t{} = {} {}'
                fstring = string_format.format(rule_string['name'], rule_string['value'], ' '.join(string_modifiers))

            else:
                if rule_string['type'] == 'text':
                    string_format = '\n\t\t{} = "{}"'
                else:
                    string_format = '\n\t\t{} = {}'
                fstring = string_format.format(rule_string['name'], rule_string['value'])

            string_container.append(fstring)

        rule_strings = '\n\tstrings:{}\n'.format(''.join(string_container))
    else:
        rule_strings = str()

    if rule.get('condition_terms'):
        # Format condition with appropriate whitespace between keywords
        cond = list()
        indents = '\n\t\t'
        for term in rule['condition_terms']:

            if condition_indents:
                if term == '(':
                    indents = indents + '\t'
                if term == ')' and len(indents) > 3:
                    indents = indents[:-1]

            if not cond:

                if term in Parser.FUNCTION_KEYWORDS:
                    cond.append(term)

                elif term in Parser.KEYWORDS:
                    cond.append(term)
                    cond.append(' ')

                else:
                    cond.append(term)

            else:

                if cond[-1][-1] in (' ', '\t') and term in Parser.FUNCTION_KEYWORDS:
                    cond.append(term)

                elif cond[-1][-1] not in (' ', '\t') and term in Parser.FUNCTION_KEYWORDS:
                    cond.append(' ')
                    cond.append(term)

                elif cond[-1][-1] in (' ', '\t') and term in Parser.KEYWORDS:
                    cond.append(term)
                    cond.append(' ')
                    if condition_indents and term in ('and', 'or'):
                        cond.append(indents)

                elif cond[-1][-1] not in (' ', '\t') and term in Parser.KEYWORDS:
                    cond.append(' ')
                    cond.append(term)
                    cond.append(' ')
                    if condition_indents and term in ('and', 'or'):
                        cond.append(indents)

                elif cond[-1][-1] in (' ', '\t') and term == ':':
                    cond.append(term)
                    cond.append(' ')

                elif cond[-1][-1] not in (' ', '\t') and term == ':':
                    cond.append(' ')
                    cond.append(term)
                    cond.append(' ')

                else:
                    cond.append(term)
                    cond.append(' ')

        fcondition = ''.join(cond).rstrip(' ')
        rule_condition = '\n\tcondition:{}{}'.format('\n\t\t', fcondition)
    else:
        rule_condition = str()

    formatted_rule = rule_format.format(
        imports=rule_imports,
        rulename=rule_name,
        tags=rule_tags,
        meta=rule_meta,
        scopes=rule_scopes,
        strings=rule_strings,
        condition=rule_condition,
    )

    return formatted_rule
