// Checks the "Supported Versions" table in SECURITY.md, and the page its scope names for
// what the secretPatterns match.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

const policy = readFileSync(new URL('../SECURITY.md', import.meta.url), 'utf8');

// Release tags published for this repository. Add a tag only once it exists:
// git ls-remote --tags https://github.com/opena2a-org/mcp-security-checklist
const RELEASE_TAGS = [];
// A version cell that names tagged releases rather than a branch.
const RELEASE_VERSION = /\b(?:tags?|tagged|releases?)\b/i;

function section(text, heading) {
  const start = text.indexOf(`## ${heading}\n`);
  assert.notEqual(start, -1, `SECURITY.md has no "## ${heading}" section`);
  const next = text.indexOf('\n## ', start + 1);
  return text.slice(start, next === -1 ? undefined : next);
}

// Splits a table row on the pipes GitHub treats as cell borders; "\|" stays in its cell.
function cells(line) {
  return line.split(/(?<!\\)\|/).slice(1, -1).map((cell) => cell.trim());
}

function versionRows(text) {
  const lines = section(text, 'Supported Versions').split('\n').filter((line) => line.startsWith('|'));
  return lines.slice(2).map((line) => {
    const [version, supported] = cells(line);
    return { line, version, supported };
  });
}

// Returns the rows that mark as supported a version a user cannot get.
function unavailableSupported(rows, tags) {
  return rows
    .filter(({ supported }) => supported === 'Yes')
    .filter(({ version }) => RELEASE_VERSION.test(version) && tags.length === 0)
    .map(({ version }) => version);
}

const rows = versionRows(policy);

test('the Supported Versions table marks each version Yes or No', () => {
  assert.ok(rows.length > 0, 'no table rows found under "Supported Versions"');
  for (const row of rows) {
    assert.ok(['Yes', 'No'].includes(row.supported), `row is not marked Yes or No: ${row.line}`);
  }
  assert.ok(rows.some(({ version, supported }) => version === 'main branch' && supported === 'Yes'),
    'the main branch is not listed as supported');
});

test('every supported version is one a user can get', () => {
  assert.deepEqual(unavailableSupported(rows, RELEASE_TAGS), [],
    'versions marked supported that do not exist; list a release only once it is tagged');
});

test('the version check flags tagged releases only while no tag exists', () => {
  const table = '## Supported Versions\n\n| Version | Supported |\n|---|---|\n| main branch | Yes |\n| Tagged releases | Yes |\n| Forks | No |\n';
  assert.deepEqual(unavailableSupported(versionRows(table), []), ['Tagged releases']);
  assert.deepEqual(unavailableSupported(versionRows(table), ['v0.1.0']), []);
  const unsupported = table.replace('| Tagged releases | Yes |', '| Tagged releases | No |');
  assert.deepEqual(unavailableSupported(versionRows(unsupported), []), []);
});

test('the policy says no tagged release exists only while that is true', () => {
  const statesNone = /no tagged releases/i.test(section(policy, 'Supported Versions'));
  assert.equal(statesNone, RELEASE_TAGS.length === 0,
    RELEASE_TAGS.length === 0
      ? 'SECURITY.md does not say that no tagged release exists yet'
      : 'SECURITY.md says no tagged release exists, but RELEASE_TAGS lists one');
});

// The Markdown pages a line names: a path in code quotes, a link target, or the README by name.
function namedDocuments(line) {
  const paths = [
    ...[...line.matchAll(/`([\w./-]+\.md)`/g)].map(([, path]) => path),
    ...[...line.matchAll(/\]\(([\w./-]+\.md)\)/g)].map(([, path]) => path),
  ];
  if (/\bREADME\b(?!\.md)/.test(line)) paths.push('README.md');
  return [...new Set(paths)];
}

test('the scope names the page that lists what the secret patterns match', () => {
  const line = section(policy, 'Reporting Vulnerabilities').split('\n').find((text) => text.includes('`secretPatterns`'));
  assert.ok(line, 'the SECURITY.md scope does not name the secretPatterns');
  const documents = namedDocuments(line);
  assert.notEqual(documents.length, 0, `names no page for what the patterns match: ${line}`);
  for (const path of documents) {
    const url = new URL(`../${path}`, import.meta.url);
    assert.ok(existsSync(url), `SECURITY.md names ${path}, which does not exist`);
    const text = readFileSync(url, 'utf8').replace(/\s+/g, ' ');
    assert.match(text, /`secretPatterns`.{0,200}They match:/, `${path} does not list what the secretPatterns match`);
  }
});

test('the page check reads the README by name, a path in code quotes and a link target', () => {
  assert.deepEqual(namedDocuments('a format the README says it matches'), ['README.md']);
  assert.deepEqual(namedDocuments('a format that `docs/reference-audit-configuration.md` lists'),
    ['docs/reference-audit-configuration.md']);
  assert.deepEqual(namedDocuments('see [the reference page](docs/reference-audit-configuration.md)'),
    ['docs/reference-audit-configuration.md']);
  assert.deepEqual(namedDocuments('`mcp-audit.json`, including its `secretPatterns`'), []);
});
