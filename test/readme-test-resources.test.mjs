// Checks the "Testing Your Defenses" table in README.md.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');

const NO_TEST = 'No dedicated test';
const LINK = /\[([^\]]+)\]\(([^)\s]+)\)/g;
// An attack category page lists tests; a single test lives at <category>/<n>.
const CATEGORY_INDEX = /^https:\/\/agentpwn\.com\/attacks\/[a-z0-9-]+\/?$/;

function section(heading) {
  const start = readme.indexOf(`## ${heading}\n`);
  assert.notEqual(start, -1, `README has no "## ${heading}" section`);
  const next = readme.indexOf('\n## ', start + 1);
  return readme.slice(start, next === -1 ? undefined : next);
}

function links(text) {
  return [...text.matchAll(LINK)].map(([, label, href]) => ({ label, href }));
}

// GitHub heading anchor: lowercase, drop punctuation, spaces become hyphens.
function slug(heading) {
  return heading.toLowerCase().replace(/[^\w\- ]/g, '').replace(/ /g, '-');
}

const testing = section('Testing Your Defenses');
const rows = testing
  .split('\n')
  .filter((line) => line.startsWith('|'))
  .slice(2)
  .map((line) => line.split('|').slice(1, -1).map((cell) => cell.trim()))
  .map(([category, description, resource]) => ({ category, description, resource }));

test('the table lists attack categories with a test resource cell', () => {
  assert.ok(rows.length > 0, 'no table rows found under "Testing Your Defenses"');
  for (const row of rows) {
    assert.ok(row.category && row.description && row.resource, `incomplete row: ${JSON.stringify(row)}`);
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
    .filter((row) => links(row.resource).length === 0 && !row.resource.includes(NO_TEST))
    .map((row) => row.category);
  assert.deepEqual(offenders, [], `rows with neither a link nor "${NO_TEST}"`);
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
