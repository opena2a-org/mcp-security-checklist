// Checks the "Testing Your Defenses" table in README.md.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');

const NO_TEST = 'No dedicated test';
// An inline link or image: [label](destination) or [label](<destination>), with
// optional spaces around the destination and an optional title in double quotes,
// single quotes or parentheses. The label, destination and title have length limits;
// a longer one, or a title holding a backslash-escaped delimiter, is not read as a
// link. The label cannot contain a bracket, so a long run of "[" is scanned in
// linear time.
const LINK = /(!?)\[([^\][]{0,300})\]\(\s*(?:<([^<>\s]{1,500})>|([^()<>\s]{1,500}))(?:\s+(?:"[^"]{0,300}"|'[^']{0,300}'|\([^()]{0,300}\)))?\s*\)/g;
// A single test lives at <category>/<n>; the category page itself only lists tests.
const TEST_PAGE = /^https:\/\/agentpwn\.com\/attacks\/([a-z0-9-]+)\/(\d+)\/?$/;
// Tests that exist on agentpwn.com, by attack category. The README names the
// three MCP exploitation tests; add a number only once its page exists.
const KNOWN_TESTS = { 'mcp-exploitation': ['1', '2', '3'] };
// Left in a resource cell once its test links are removed, any of these could
// still render as a link: a URL, an autolink or HTML tag, or link brackets.
const LINK_LEFTOVER = /https?:|www\.|<|\[|\]|@/i;
// A link label is read one word (a run without spaces) at a time, after dropping the
// sentence punctuation that may follow it, so a long label is scanned in linear time.
const TRAILING_PUNCTUATION = '.,;:!?';
// A word that is an address: one holding "://", "www." or "mailto:", or a domain
// followed by a path, a query, a fragment or a port.
const ADDRESS_WORD = /:\/\/|www\.|mailto:|^[a-z0-9.-]+\.[a-z]{2,}(?:[/?#]|:\d)/i;
// A domain with nothing after it is an address only when it is the whole label; next to
// other text it reads as a name ("Node.js guide", "Built on Node.js").
const BARE_DOMAIN = /^[a-z0-9.-]+\.[a-z]{2,}$/i;

function section(heading) {
  const start = readme.indexOf(`## ${heading}\n`);
  assert.notEqual(start, -1, `README has no "## ${heading}" section`);
  const next = readme.indexOf('\n## ', start + 1);
  return readme.slice(start, next === -1 ? undefined : next);
}

function links(text) {
  return [...text.matchAll(LINK)].map(([, image, label, angled, plain]) => ({
    image: image === '!',
    label,
    href: angled ?? plain,
  }));
}

// GitHub heading anchor: lowercase, drop punctuation, spaces become hyphens.
function slug(heading) {
  return heading.toLowerCase().replace(/[^\w\- ]/g, '').replace(/ /g, '-');
}

function isKnownTest(href) {
  const match = TEST_PAGE.exec(href);
  return Boolean(match && KNOWN_TESTS[match[1]]?.includes(match[2]));
}

function trimTrailingPunctuation(word) {
  let end = word.length;
  while (end > 0 && TRAILING_PUNCTUATION.includes(word[end - 1])) end -= 1;
  return word.slice(0, end);
}

// Returns each address in the label, as written and without its trailing punctuation.
// Invisible format characters (such as a zero-width space) are dropped first, so they
// cannot split or end an address.
function labelAddresses(label) {
  const words = label
    .replace(/\p{Cf}/gu, '')
    .split(/\s+/)
    .map((written) => ({ written, address: trimTrailingPunctuation(written) }))
    .filter(({ address }) => address);
  return words.filter(({ address }) => ADDRESS_WORD.test(address) || (words.length === 1 && BARE_DOMAIN.test(address)));
}

// True when an address in the label names a different destination: the target must
// equal each address, with or without its trailing punctuation, as written, with
// "https://" in front, or with "./" in front (a file name).
function labelMismatch({ label, href }) {
  return labelAddresses(label).some(({ written, address }) =>
    ![written, address].some((form) => [form, `https://${form}`, `./${form}`].includes(href)));
}

// Splits a table row on the pipes GitHub treats as cell borders; "\|" stays in its cell.
function cells(line) {
  return line.split(/(?<!\\)\|/).slice(1, -1).map((cell) => cell.trim());
}

function tableRows(text) {
  const lines = text.split('\n').filter((line) => line.startsWith('|'));
  const width = lines.length > 0 ? cells(lines[0]).length : 0;
  return lines.slice(2).map((line) => {
    const row = cells(line);
    const [category, description, resource] = row;
    return { line, width, cellCount: row.length, category, description, resource };
  });
}

// Returns why a Test Resource cell is not acceptable, or null when it is.
function resourceProblem(resource) {
  let testLinks = 0;
  const rest = resource.replace(LINK, (whole, image, label, angled, plain) => {
    // Raw HTML or an autolink inside the label could link somewhere else.
    if (image || label.includes('<') || !isKnownTest(angled ?? plain)) return whole;
    testLinks += 1;
    return '';
  });
  if (LINK_LEFTOVER.test(rest)) return 'links a page that is not a known agentpwn test, or holds link syntax the check cannot read';
  if (testLinks === 0 && !resource.includes(NO_TEST)) return `has neither a test link nor "${NO_TEST}"`;
  return null;
}

const testing = section('Testing Your Defenses');
const rows = tableRows(testing);

test('the table lists attack categories with a test resource cell', () => {
  assert.ok(rows.length > 0, 'no table rows found under "Testing Your Defenses"');
  for (const row of rows) {
    assert.equal(row.cellCount, row.width, `row has ${row.cellCount} cells, header has ${row.width}: ${row.line}`);
    assert.ok(row.category && row.description && row.resource, `incomplete row: ${row.line}`);
  }
});

test('every row links a specific test or states that none exists', () => {
  const offenders = rows
    .map((row) => ({ category: row.category, problem: resourceProblem(row.resource) }))
    .filter(({ problem }) => problem !== null);
  assert.deepEqual(offenders, [], 'rows whose Test Resource cell is not a known agentpwn test link or "No dedicated test"');
});

test('the resource check rejects every link that is not a known test', () => {
  const learn = 'https://agentpwn.com/learn';
  const page = 'https://agentpwn.com/attacks/mcp-exploitation/3';
  const cellsWithOtherLinks = [
    // Each of the next four carries one link marker only, so dropping that marker from the check fails here.
    'No dedicated test. See <br>',
    'No dedicated test. Mail security@example.com',
    'No dedicated test. See [course',
    'No dedicated test. See course]',
    `No dedicated test. See [course [beta]](${learn})`,
    `No dedicated test. See [course \\[beta\\]](${learn})`,
    `No dedicated test. See [course]( ${learn} )`,
    `No dedicated test. See [](${learn})`,
    `No dedicated test. See [a\\|b](${learn})`,
    `No dedicated test. See [![x](https://agentpwn.com/attacks/mcp-exploitation/3)](${learn})`,
    `No dedicated test. See [course](${learn} "x")`,
    `No dedicated test. See ${learn}`,
    `No dedicated test. See <${learn}>`,
    'No dedicated test. See [course][learn]',
    `No dedicated test. See <a href="${learn}">course</a>`,
    'No dedicated test. See www.agentpwn.com/learn',
    '[t](https://agentpwn.com/attacks/mcp-exploitation/99)',
    '[t](https://agentpwn.com/attacks/prompt-injection/1)',
    `[t](${page}/extra)`,
    `[t](${page}?utm=1)`,
    `[t](https://evil.example/${page})`,
    '[t](http://agentpwn.com/attacks/mcp-exploitation/3)',
    '[MCP exploitation](https://agentpwn.com/attacks/mcp-exploitation)',
    '[MCP exploitation](https://agentpwn.com/attacks/mcp-exploitation/)',
    `[<a href="https://example.com">x</a>](${page})`,
    `![t](${page})`,
    'Not covered',
  ];
  for (const resource of cellsWithOtherLinks) {
    const [row] = tableRows(`| A | B | C |\n|---|---|---|\n| Category | Description | ${resource} |\n`);
    assert.equal(row.cellCount, 3, `pipe split broke the row: ${resource}`);
    assert.notEqual(resourceProblem(row.resource), null, `accepted: ${resource}`);
  }
});

test('the resource check accepts a known test link with a plain, spaced or angled destination and an optional title in each delimiter', () => {
  const page = 'https://agentpwn.com/attacks/mcp-exploitation/3';
  const accepted = [
    `[agentpwn.com/attacks/mcp-exploitation/3](${page})`,
    `[t](<${page}>)`,
    `[t]( ${page} )`,
    `[t](${page} "Cross-Tool Exploit Chain")`,
    `[t](${page} 'Cross-Tool Exploit Chain')`,
    `[t](${page} (Cross-Tool Exploit Chain))`,
    `No dedicated test. Closest: [t](${page}), which is near`,
    NO_TEST,
  ];
  for (const resource of accepted) {
    assert.equal(resourceProblem(resource), null, `rejected: ${resource}`);
  }
});

test('a row with an unescaped pipe has more cells than the header', () => {
  const [row] = tableRows('| A | B | C |\n|---|---|---|\n| Category | Description | [a|b](https://agentpwn.com/learn) |\n');
  assert.notEqual(row.cellCount, row.width);
});

test('the link pattern scans a long run of "[" in linear time', () => {
  const start = performance.now();
  links('['.repeat(100000));
  const elapsed = performance.now() - start;
  // A quadratic scan of this input takes seconds; a linear one takes milliseconds.
  assert.ok(elapsed < 500, `took ${Math.round(elapsed)} ms`);
});

test('the label check reads a long label in linear time', () => {
  const page = 'https://agentpwn.com/attacks/mcp-exploitation/3';
  for (const [name, label] of [
    ['a run of "a"', 'a'.repeat(100000)],
    ['a run of "." before a letter', `${'.'.repeat(100000)}a`],
    ['a dotted run', 'a.'.repeat(50000)],
  ]) {
    const start = performance.now();
    labelMismatch({ label, href: page });
    const elapsed = performance.now() - start;
    // A quadratic scan of this input takes seconds; a linear one takes milliseconds.
    assert.ok(elapsed < 500, `${name} took ${Math.round(elapsed)} ms`);
  }
});

test('a link whose label holds an address points at that address', () => {
  for (const link of links(testing)) {
    assert.ok(!labelMismatch(link), `label and target differ for [${link.label}](${link.href})`);
  }
});

test('the label check flags an address in a label that names another destination', () => {
  const page = 'https://agentpwn.com/attacks/mcp-exploitation/3';
  const flagged = [
    'agentpwn.com/attacks/mcp-exploitation/2',
    'evil.example',
    'cdn.evil-2.example',
    'evil.example:8080/x',
    'evil.example?x=1',
    'evil.io#x',
    'www.evil.example',
    'WWW.EVIL.EXAMPLE',
    'See www.evil.example',
    'https://evil.example',
    'mailto:security@evil.example',
    'agentpwn.com/attacks/mcp-exploitation/3 or https://evil.example',
    // A domain followed by a path, a query, a fragment or a port is an address after other text too.
    'agentpwn.com/attacks/mcp-exploitation/3 see evil.example/x',
    'See evil.example:8080',
    'See https://evil.example.',
    'evil.example.',
    // Any whitespace separates words, and the empty words around it are dropped.
    'See\tevil.example/x',
    ' evil.example',
    'evil.example ',
    // Each address pattern ignores case.
    'See EVIL.EXAMPLE/x',
    'EVIL.EXAMPLE',
    // An invisible format character does not hide an address.
    'evil.example​',
    'evil.​example',
  ];
  for (const label of flagged) {
    assert.ok(labelMismatch({ label, href: page }), `not flagged: [${label}]`);
  }
  const matching = [
    ...[
      'agentpwn.com/attacks/mcp-exploitation/3',
      page,
      `Test: ${page}`,
      'MCP exploitation',
      'Tests',
      '3. Input Validation and Sanitization',
      // A dotted name followed by a space or other text, or after other text, reads as a name.
      'Node.js guide',
      'Node.js: a guide',
      'evil.example is bad',
      'evil.example, test 3',
      'Built on Node.js',
      'i.e',
      // Sentence punctuation after an address is not part of it.
      `See ${page}.`,
      `${page}, test 3`,
      'agentpwn.com/attacks/mcp-exploitation/3!',
      `See\t${page}.`,
    ].map((label) => ({ label, href: page })),
    // A target that ends in sentence punctuation matches a label written the same way.
    { label: `${page}.`, href: `${page}.` },
    { label: `${page}?`, href: `${page}?` },
    // A file name reads like a domain; it matches a target written the same way or with "./" in front.
    { label: 'SECURITY.md', href: 'SECURITY.md' },
    { label: 'mcp-audit.json', href: 'mcp-audit.json' },
    { label: 'mcp-audit.json', href: './mcp-audit.json' },
  ];
  for (const link of matching) {
    assert.ok(!labelMismatch(link), `flagged: [${link.label}](${link.href})`);
  }
});

test('in-page links resolve to a README heading', () => {
  const anchors = new Set([...readme.matchAll(/^#{1,6} (.+)$/gm)].map(([, heading]) => slug(heading)));
  for (const { label, href } of links(readme)) {
    if (href.startsWith('#')) {
      assert.ok(anchors.has(href.slice(1)), `[${label}](${href}) matches no heading`);
    }
  }
});
