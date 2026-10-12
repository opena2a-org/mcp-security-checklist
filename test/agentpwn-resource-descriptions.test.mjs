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

// A link to the guides page, a word that files an entry under testing, and a list item.
const GUIDES_LINK = '](https://agentpwn.com/tools)';
const TESTING = /\btest(?:ing|s)?\b/i;
const LIST_ITEM = /^\s*(?:[-*+]|\d+\.) /;

// Each list item in the text with its lead-in: the last sentence of the nearest
// paragraph or heading above the list.
function listItems(text) {
  const items = [];
  let paragraph = [];
  let leadIn = '';
  for (const line of text.split('\n')) {
    const item = LIST_ITEM.test(line);
    if (!item && line.trim() !== '') {
      paragraph.push(line.trim());
      continue;
    }
    if (paragraph.length > 0) leadIn = paragraph.join(' ').split(/(?<=[.:!?]) /).at(-1);
    paragraph = [];
    if (item) items.push({ item: line.trim(), leadIn });
  }
  return items;
}

// Returns the list entries for the guides page whose lead-in presents the list as testing.
function guidesListedAsTesting(text) {
  return listItems(text)
    .filter(({ item, leadIn }) => item.includes(GUIDES_LINK) && TESTING.test(leadIn))
    .map(({ item, leadIn }) => `${leadIn} ${item}`);
}

// Every string value in the configuration, with the key path that leads to it.
function strings(value, path = []) {
  if (typeof value === 'string') return [{ path, value }];
  if (value === null || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, child]) => strings(child, [...path, key]));
}

test('SECURITY.md describes agentpwn.com/tools as security guides, not testing tools', () => {
  const lines = security.split('\n').filter((line) => line.includes(GUIDES_LINK));
  assert.notEqual(lines.length, 0, 'SECURITY.md has no link to agentpwn.com/tools');
  for (const line of lines) {
    assert.doesNotMatch(line, /\btest(?:ing|s)?\b/i, `describes the guides page as testing: ${line}`);
    assert.match(line, /security guides/i, `does not call the page security guides: ${line}`);
  }
});

test('SECURITY.md does not list agentpwn.com/tools under a lead-in about testing', () => {
  assert.deepEqual(guidesListedAsTesting(security), [], 'the guides page is listed as a testing resource');
});

test('the lead-in check flags a guides entry in a list of testing environments', () => {
  const guides = '- [agentpwn.com/tools](https://agentpwn.com/tools) -- security guides for AI tools and MCP servers';
  const honeypot = '- [agentpwn.com](https://agentpwn.com) -- honeypot environment';
  const testing = 'We encourage security testing of MCP deployments. For safe, controlled testing environments:';
  assert.deepEqual(guidesListedAsTesting(`${testing}\n\n${honeypot}\n${guides}\n`), [
    `For safe, controlled testing environments: ${guides}`,
  ]);
  // The lead-in is the sentence that introduces the list, not the paragraph before it.
  const reading = 'We encourage security testing of MCP deployments. For written guidance:';
  assert.deepEqual(guidesListedAsTesting(`${reading}\n${guides}\n`), []);
  // A heading or a paragraph ends the list above it.
  const sections = `## Security Testing\n\n${honeypot}\n\n## Further Reading\n\n${guides}\n`;
  assert.deepEqual(guidesListedAsTesting(sections), []);
  assert.deepEqual(guidesListedAsTesting(`## Security Testing\n\n${honeypot}\n${guides}\n`), [
    `## Security Testing ${guides}`,
  ]);
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
