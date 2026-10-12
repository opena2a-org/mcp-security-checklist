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
const HEADING = /^ {0,3}#{1,6}(?:\s|$)/;
// The blocks that the text of a list item cannot run into: a thematic break, a code
// fence, a block quote and an HTML block. An HTML block opens with a comment, a
// declaration or one of the block-level tags, not with an inline tag or an autolink.
const THEMATIC_BREAK = /^ {0,3}([-*_])[ \t]*(?:\1[ \t]*){2,}$/;
const FENCE = /^ {0,3}(`{3,}(?!.*`)|~{3,})/;
const BLOCK_QUOTE = /^ {0,3}>/;
const HTML_TAGS =
  'address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|' +
  'fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|' +
  'menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|' +
  'track|ul';
const HTML_BLOCK = new RegExp(
  '^ {0,3}<(?:!--|\\?|![a-z]|!\\[CDATA\\[|(?:pre|script|style|textarea)(?:[ \\t>]|$)|' +
    `/?(?:${HTML_TAGS})(?:[ \\t>]|/>|$))`,
  'i',
);

// Each list item in the text with its lead-in: the last sentence of the nearest
// paragraph or heading above the list.
function listItems(text) {
  const items = [];
  let paragraph = [];
  let leadIn = '';
  let current = null;
  let column = 0;
  let fence = null;
  for (const line of text.split('\n')) {
    // The lines of a fenced code block are code, up to the fence that closes it.
    if (fence) {
      if (fence.test(line)) fence = null;
      continue;
    }
    // A thematic break written with spaces (- - -) is not a list item.
    const rule = THEMATIC_BREAK.test(line);
    const item = !rule && LIST_ITEM.test(line);
    const blank = line.trim() === '';
    const opener = FENCE.exec(line);
    // A line left of the item's text that opens one of those blocks ends the item;
    // the same line indented to the item's text is inside the item.
    const block = rule || opener || BLOCK_QUOTE.test(line) || HTML_BLOCK.test(line);
    const outside = block && line.search(/\S/) < column;
    // A non-blank line right after a list item continues that item, unless it is
    // an item or a heading itself, or it opens a block outside the item.
    if (current && !item && !blank && !HEADING.test(line) && !outside) {
      current.item += ` ${line.trim()}`;
      continue;
    }
    current = null;
    if (opener) fence = new RegExp(`^ {0,3}${opener[1][0]}{${opener[1].length},}[ \\t]*$`);
    // A thematic break and a code fence end a paragraph and are not part of one.
    if (!item && !blank && !rule && !opener) {
      paragraph.push(line.trim());
      continue;
    }
    if (paragraph.length > 0) leadIn = paragraph.join(' ').split(/(?<=[.:!?]) /).at(-1);
    paragraph = [];
    if (item) {
      current = { item: line.trim(), leadIn };
      // The text of an item starts after its marker and one to four spaces.
      const [, marker, gap] = /^(\s*(?:[-*+]|\d+\.))( {1,4}(?=\S))?/.exec(line);
      column = marker.length + (gap ? gap.length : 1);
      items.push(current);
    }
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
  // The continuation line of a wrapped list item belongs to that item, not to a new lead-in.
  const wrapped = '- [agentpwn.com](https://agentpwn.com) -- honeypot environment for testing agent\n  security tools';
  assert.deepEqual(guidesListedAsTesting(`${testing}\n\n${wrapped}\n${guides}\n`), [
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
  // A heading right after a list item is not part of that item.
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n## Security Testing\n${guides}\n`), [
    `## Security Testing ${guides}`,
  ]);
  // A thematic break, code fence, block quote or HTML block right after a list item ends
  // the list, so the sentence written after it introduces the next list.
  const environments = 'For safe, controlled testing environments:';
  for (const block of ['---', '* * *', '```sh\nnpm run audit\n```']) {
    const text = `${reading}\n\n${honeypot}\n${block}\n${environments}\n${guides}\n`;
    assert.deepEqual(guidesListedAsTesting(text), [`${environments} ${guides}`], `the list runs past ${block}`);
  }
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n> ${environments}\n${guides}\n`), [
    `> ${environments} ${guides}`,
  ]);
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n<p>${environments}</p>\n\n${guides}\n`), [
    `<p>${environments}</p> ${guides}`,
  ]);
  // The lines of a code fence are code, not a lead-in.
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n\`\`\`sh\nnpm test\n\`\`\`\n${guides}\n`), []);
  // A block indented to the text of a list item is inside that item.
  assert.deepEqual(guidesListedAsTesting(`${reading}\n\n${honeypot}\n  > used for testing\n${guides}\n`), []);
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
