// Checks how SECURITY.md and mcp-audit.json describe the agentpwn.com pages they link.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const security = readFileSync(new URL('../SECURITY.md', import.meta.url), 'utf8');
const audit = JSON.parse(readFileSync(new URL('../mcp-audit.json', import.meta.url), 'utf8'));

// agentpwn.com/tools holds security guides for AI tools and MCP servers, not testing tools.
const GUIDES = /^https:\/\/agentpwn\.com\/tools\/?$/;
// A single test lives at <category>/<n>; it holds one test, not a set of attack patterns.
const TEST_PAGE = /^https:\/\/agentpwn\.com\/attacks\/[a-z0-9-]+\/\d+\/?$/;

// Every string value in the configuration, with the key path that leads to it.
function strings(value, path = []) {
  if (typeof value === 'string') return [{ path, value }];
  if (value === null || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, child]) => strings(child, [...path, key]));
}

test('SECURITY.md describes agentpwn.com/tools as security guides, not testing tools', () => {
  const lines = security.split('\n').filter((line) => line.includes('](https://agentpwn.com/tools)'));
  assert.notEqual(lines.length, 0, 'SECURITY.md has no link to agentpwn.com/tools');
  for (const line of lines) {
    assert.doesNotMatch(line, /\btest(?:ing|s)?\b/i, `describes the guides page as testing: ${line}`);
    assert.match(line, /security guides/i, `does not call the page security guides: ${line}`);
  }
});

test('mcp-audit.json does not name agentpwn.com/tools as a testing resource', () => {
  const links = strings(audit).filter(({ value }) => GUIDES.test(value));
  const testing = links.filter(({ path }) => /test/i.test(path.at(-1))).map(({ path }) => path.join('.'));
  assert.deepEqual(testing, [], 'keys that name the guides page as a testing resource');
});

test('mcp-audit.json does not give a single agentpwn test page as a source of attack patterns', () => {
  const single = strings(audit)
    .filter(({ path, value }) => /attackPattern/i.test(path.at(-1)) && TEST_PAGE.test(value))
    .map(({ path, value }) => `${path.join('.')}: ${value}`);
  assert.deepEqual(single, [], 'attack pattern keys that point at one test page');
});
