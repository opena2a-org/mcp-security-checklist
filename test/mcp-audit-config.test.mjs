// Checks the MCP protocol version named in mcp-audit.json and what README.md says about it.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const config = JSON.parse(readFileSync(new URL('../mcp-audit.json', import.meta.url), 'utf8'));
const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');

// MCP names each revision of its specification by date (YYYY-MM-DD). Add a revision
// here once it is published at https://modelcontextprotocol.io/specification/versioning.
const PUBLISHED_REVISIONS = ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28'];
// The last revision in which a client and server agree on a version in the initialize
// handshake. From 2026-07-28 there is no handshake: every request declares its version.
const LAST_HANDSHAKE_REVISION = '2025-11-25';
const DATED_VERSION = /^(\d{4})-(\d{2})-(\d{2})$/;

function isCalendarDate(value) {
  const match = DATED_VERSION.exec(value);
  if (!match) return false;
  const date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
  return date.toISOString().slice(0, 10) === value;
}

// The "Reference Audit Configuration" section of the README, up to the next "## " heading.
function auditSection() {
  const start = readme.indexOf('## Reference Audit Configuration\n');
  assert.notEqual(start, -1, 'README has no "## Reference Audit Configuration" section');
  const next = readme.indexOf('\n## ', start + 1);
  return readme.slice(start, next === -1 ? undefined : next);
}

// A sentence about the handshake, whichever word it uses for it.
const HANDSHAKE = /initiali[sz]|handshake|negotiat/i;
// The scope such a sentence has to carry: the last revision that has the handshake,
// with or without code quotes, "and earlier".
const HANDSHAKE_SCOPE = new RegExp(`\`?${LAST_HANDSHAKE_REVISION}\`? and earlier`);

// Returns the sentences about the handshake that do not limit it to the last revision
// that has one and the revisions before it, so that they read as true of every revision
// or of the wrong ones.
function unscopedHandshakeSentences(text) {
  return text
    .replace(/\s+/g, ' ')
    .split(/(?<=\.) /)
    .filter((sentence) => HANDSHAKE.test(sentence) && !HANDSHAKE_SCOPE.test(sentence));
}

test('the audit target names its MCP revision as protocolVersion', () => {
  const { target } = config.audit;
  assert.equal(
    'protocol' in target,
    false,
    `target.protocol is "${target.protocol}"; MCP has no such version label, name the revision in target.protocolVersion`,
  );
  assert.equal(typeof target.protocolVersion, 'string', 'target.protocolVersion is missing');
});

test('the protocol version is a dated MCP revision that a client and server can negotiate', () => {
  const version = config.audit.target.protocolVersion;
  assert.ok(isCalendarDate(version), `"${version}" is not a YYYY-MM-DD date`);
  assert.ok(
    PUBLISHED_REVISIONS.includes(version),
    `"${version}" is not a published MCP revision (${PUBLISHED_REVISIONS.join(', ')})`,
  );
});

test('the date check rejects version labels that are not dates', () => {
  for (const value of ['mcp-v1', '1.0', '2026-7-28', '2026-02-30', '2026-13-01', ' 2026-07-28']) {
    assert.equal(isCalendarDate(value), false, `"${value}" was read as a date`);
  }
  assert.equal(isCalendarDate('2026-07-28'), true);
});

test('the README says protocolVersion names the revision under audit', () => {
  const text = auditSection();
  assert.match(text, /`(?:target\.)?protocolVersion`/, 'the section does not mention protocolVersion');
  assert.match(text, /revision/i, 'the section does not say protocolVersion names a revision');
});

test('the README limits the initialize handshake to the revisions that have one', () => {
  const unscoped = unscopedHandshakeSentences(auditSection());
  assert.deepEqual(
    unscoped,
    [],
    `only revisions ${LAST_HANDSHAKE_REVISION} and earlier have an initialize handshake: ${unscoped.join(' ')}`,
  );
});

test('the handshake check flags a sentence that gives every revision an initialize handshake', () => {
  const every = 'Each revision is a date, and a client and server negotiate it during initialization.';
  const earlier = 'In revisions `2025-11-25` and earlier, a client and server agree on it in the\n`initialize` handshake.';
  assert.deepEqual(unscopedHandshakeSentences(`${every}\n${earlier}`), [every]);
});

test('the handshake check flags a sentence that does not use the word initialization', () => {
  const handshake = 'A client and server negotiate it in the handshake.';
  const negotiation = 'The two sides settle the revision by negotiation.';
  const unrelated = 'Every request declares that date in its `_meta` field.';
  assert.deepEqual(unscopedHandshakeSentences(`${handshake}\n${negotiation}\n${unrelated}`), [handshake, negotiation]);
});

test('the handshake check flags a sentence that names the last revision but not the earlier ones', () => {
  const since = 'Since `2025-11-25`, a client and server agree on it in the `initialize` handshake.';
  const only = 'Revision 2025-11-25 has an initialize handshake.';
  const earlier = 'In revisions 2025-11-25 and\nearlier, a client and server agree on it in the handshake.';
  assert.deepEqual(unscopedHandshakeSentences(`${since}\n${only}\n${earlier}`), [since, only]);
});
