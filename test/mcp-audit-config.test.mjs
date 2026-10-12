// Checks the MCP protocol version named in mcp-audit.json.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const config = JSON.parse(readFileSync(new URL('../mcp-audit.json', import.meta.url), 'utf8'));
const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');

// MCP names each revision of its specification by date (YYYY-MM-DD), and a client
// and server negotiate one of these strings during initialization. Add a revision
// here once it is published at https://modelcontextprotocol.io/specification/versioning.
const PUBLISHED_REVISIONS = ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28'];
const DATED_VERSION = /^(\d{4})-(\d{2})-(\d{2})$/;

function isCalendarDate(value) {
  const match = DATED_VERSION.exec(value);
  if (!match) return false;
  const date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
  return date.toISOString().slice(0, 10) === value;
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
  const start = readme.indexOf('## Reference Audit Configuration\n');
  assert.notEqual(start, -1, 'README has no "## Reference Audit Configuration" section');
  const next = readme.indexOf('\n## ', start + 1);
  const text = readme.slice(start, next === -1 ? undefined : next);
  assert.match(text, /`(?:target\.)?protocolVersion`/, 'the section does not mention protocolVersion');
  assert.match(text, /revision/i, 'the section does not say protocolVersion names a revision');
});
