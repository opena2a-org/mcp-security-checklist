// Checks the "Testing Your Defenses" table in README.md.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');

const NO_TEST = 'No dedicated test';
// An inline link or image: [label](destination) or [label](<destination>), with
// optional spaces around the destination and an optional quoted title. Both parts
// are bounded and the label cannot contain a bracket, so a long run of "[" is
// scanned in linear time.
const LINK = /(!?)\[([^\][]{0,300})\]\(\s*(?:<([^<>\s]{1,500})>|([^()<>\s]{1,500}))(?:\s+"[^"]{0,300}")?\s*\)/g;
// An attack category page lists tests; a single test lives at <category>/<n>.
const CATEGORY_INDEX = /^https:\/\/agentpwn\.com\/attacks\/[a-z0-9-]+\/?$/;
const TEST_PAGE = /^https:\/\/agentpwn\.com\/attacks\/([a-z0-9-]+)\/(\d+)\/?$/;
// Tests that exist on agentpwn.com, by attack category. The README names the
// three MCP exploitation tests; add a number only once its page exists.
const KNOWN_TESTS = { 'mcp-exploitation': ['1', '2', '3'] };
// Left in a resource cell once its test links are removed, any of these could
// still render as a link: a URL, an autolink or HTML tag, or link brackets.
const LINK_LEFTOVER = /https?:|www\.|<|\[|\]|@/i;

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
    if (image || !isKnownTest(angled ?? plain)) return whole;
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

test('no row cites an attack category index page as its test', () => {
  const offenders = rows
    .filter((row) => links(row.resource).some(({ href }) => CATEGORY_INDEX.test(href)))
    .map((row) => row.category);
  assert.deepEqual(offenders, [], 'rows linking a category index instead of a specific test');
});

test('every row links a specific test or states that none exists', () => {
  const offenders = rows
    .map((row) => ({ category: row.category, problem: resourceProblem(row.resource) }))
    .filter(({ problem }) => problem !== null);
  assert.deepEqual(offenders, [], 'rows whose Test Resource cell is not a known agentpwn test link or "No dedicated test"');
});

test('the resource check rejects every link that is not a known test', () => {
  const learn = 'https://agentpwn.com/learn';
  const cellsWithOtherLinks = [
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
    '![t](https://agentpwn.com/attacks/mcp-exploitation/3)',
    'Not covered',
  ];
  for (const resource of cellsWithOtherLinks) {
    const [row] = tableRows(`| A | B | C |\n|---|---|---|\n| Category | Description | ${resource} |\n`);
    assert.equal(row.cellCount, 3, `pipe split broke the row: ${resource}`);
    assert.notEqual(resourceProblem(row.resource), null, `accepted: ${resource}`);
  }
});

test('the resource check accepts a known test link in every form GitHub renders as a link', () => {
  const page = 'https://agentpwn.com/attacks/mcp-exploitation/3';
  const accepted = [
    `[agentpwn.com/attacks/mcp-exploitation/3](${page})`,
    `[t](<${page}>)`,
    `[t]( ${page} )`,
    `[t](${page} "Cross-Tool Exploit Chain")`,
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

test('a link labelled with a URL points at that URL', () => {
  for (const { label, href } of links(testing)) {
    if (/^[a-z0-9.-]+\.[a-z]+\//.test(label)) {
      assert.equal(href, `https://${label}`, `label and target differ for [${label}]`);
    }
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
