// Checks the "Testing Your Defenses" table and the links in README.md, and that the
// configuration excerpt under "Reference Audit Configuration" matches mcp-audit.json.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const auditConfig = JSON.parse(readFileSync(new URL('../mcp-audit.json', import.meta.url), 'utf8'));

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
// Resources whose address this check knows: the label each is linked under, where it
// lives, and an address that must not be given for it. oasb.org, with any subdomain,
// belongs to an unrelated organization. The Agent Threat Matrix is in the
// opena2a-standards account; the same repository name under opena2a-org only redirects
// there. A longer domain or repository name is a different one and is not matched.
const KNOWN_HOMES = [
  { label: 'OASB Standard', home: 'https://oasb.ai', wrong: /(?<![\w-])oasb\.org(?!\.?[\w-])/i },
  {
    label: 'Agent Threat Matrix',
    home: 'https://github.com/opena2a-standards/agent-threat-matrix',
    wrong: /(?<![\w-])github\.com\/opena2a-org\/agent-threat-matrix(?![\w-])/i,
  },
];

function section(heading) {
  const start = readme.indexOf(`## ${heading}\n`);
  assert.notEqual(start, -1, `README has no "## ${heading}" section`);
  const next = readme.indexOf('\n## ', start + 1);
  return readme.slice(start, next === -1 ? undefined : next);
}

// A "### " checklist section, up to the next heading of level 2 or 3. A "# " line in a
// code block is a shell comment, not a heading, so it does not end the section.
function subsection(heading) {
  const start = readme.indexOf(`\n### ${heading}\n`) + 1;
  assert.notEqual(start, 0, `README has no "### ${heading}" section`);
  const next = readme.slice(start + 1).search(/\n#{2,3} /);
  return readme.slice(start, next === -1 ? undefined : start + 1 + next);
}

// Each blockquote note in the text, its lines joined with spaces and the "> " removed.
function notes(text) {
  return text
    .split(/\n\s*\n/)
    .map((block) => block.trim())
    .filter((block) => block.startsWith('>'))
    .map((block) => block.split('\n').map((line) => line.replace(/^\s*>\s?/, '')).join(' '));
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
// Invisible characters are dropped first, so they cannot split or end an address: the
// format characters (such as a zero-width space) and the other characters Unicode marks
// as default-ignorable (such as the combining grapheme joiner and variation selectors).
// Neither class holds the other: some format characters, such as U+070F, are not
// default-ignorable.
function labelAddresses(label) {
  const words = label
    .replace(/[\p{Cf}\p{Default_Ignorable_Code_Point}]/gu, '')
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

// True when a link labelled with a known resource's name points anywhere but its home.
function wrongHome({ label, href }) {
  const known = KNOWN_HOMES.find((resource) => resource.label === label);
  return known !== undefined && href !== known.home;
}

// Returns the known resources a text gives a wrong address for, wherever the address is:
// in a link, a bare URL, an HTML tag or plain text.
function wrongAddresses(text) {
  return KNOWN_HOMES.filter(({ wrong }) => wrong.test(text)).map(({ label }) => label);
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

test('the input validation section does not offer an agentpwn link as an input validation test while the table lists none', () => {
  const row = rows.find(({ category }) => category === 'Parameter injection');
  assert.ok(row, 'no "Parameter injection" row under "Testing Your Defenses"');
  if (links(row.resource).some(({ href }) => isKnownTest(href))) return;
  const claims = notes(subsection('3. Input Validation and Sanitization'))
    .filter((note) => note.includes('agentpwn.com') && /input validation/i.test(note));
  assert.deepEqual(claims, [], 'notes that offer an agentpwn link as an input validation test, though "Parameter injection" has no dedicated test');
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
  const ZERO_WIDTH_SPACE = String.fromCodePoint(0x200b);
  const COMBINING_GRAPHEME_JOINER = String.fromCodePoint(0x034f);
  const VARIATION_SELECTOR_1 = String.fromCodePoint(0xfe00);
  const VARIATION_SELECTOR_16 = String.fromCodePoint(0xfe0f);
  const VARIATION_SELECTOR_17 = String.fromCodePoint(0xe0100);
  const RIGHT_TO_LEFT_OVERRIDE = String.fromCodePoint(0x202e);
  const codePointName = (codePoint) => `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
  // Every format character that is not default-ignorable, read from the Unicode tables at
  // run time so the list stays complete when Unicode adds one.
  const formatNotIgnorable = [];
  for (let codePoint = 0; codePoint <= 0x10ffff; codePoint += 1) {
    const character = String.fromCodePoint(codePoint);
    if (/\p{Cf}/u.test(character) && !/\p{Default_Ignorable_Code_Point}/u.test(character)) {
      formatNotIgnorable.push(character);
    }
  }
  // The Syriac abbreviation mark, the interlinear annotation anchor and the Egyptian
  // hieroglyph vertical joiner are in the list, so a broken read cannot leave it empty.
  for (const codePoint of [0x070f, 0xfff9, 0x13430]) {
    assert.ok(formatNotIgnorable.includes(String.fromCodePoint(codePoint)), `${codePointName(codePoint)} is missing`);
  }
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
    // An invisible character does not hide an address, whether it is a format character
    // (the zero-width space) or a mark (the combining grapheme joiner, a variation
    // selector). Each one is built at run time so the source file holds no invisible
    // character.
    `evil.example${ZERO_WIDTH_SPACE}`,
    `evil.${ZERO_WIDTH_SPACE}example`,
    `evil.exam${COMBINING_GRAPHEME_JOINER}ple`,
    `evil.example${COMBINING_GRAPHEME_JOINER}`,
    `evil.example${VARIATION_SELECTOR_1}`,
    `evil.example${VARIATION_SELECTOR_16}`,
    `evil.exam${VARIATION_SELECTOR_16}ple`,
    `evil.example${VARIATION_SELECTOR_17}`,
    // A bidirectional override, a format character often used to disguise a link, is
    // dropped like any other.
    `evil.${RIGHT_TO_LEFT_OVERRIDE}example`,
    // Some format characters are not default-ignorable (prepended concatenation marks,
    // interlinear annotation controls, Egyptian hieroglyph format controls); each one is
    // dropped too, after a dot, inside a word and at the end.
    ...formatNotIgnorable.flatMap((character) => [
      `evil.${character}example`,
      `evil.exam${character}ple`,
      `evil.example${character}`,
    ]),
  ];
  // Every failing label is collected, so one run names all of them. A character outside
  // printable ASCII is shown as <U+XXXX>, since most of these are invisible.
  const visible = (label) => label.replace(/[^\x20-\x7e]/gu, (character) => `<${codePointName(character.codePointAt(0))}>`);
  const notFlagged = flagged.filter((label) => !labelMismatch({ label, href: page })).map(visible);
  assert.deepEqual(notFlagged, [], 'labels that name another destination but are not flagged');
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
  const wronglyFlagged = matching.filter((link) => labelMismatch(link));
  assert.deepEqual(wronglyFlagged, [], 'links whose label matches the target but are flagged');
});

test('a link labelled with a known resource points at where that resource lives', () => {
  const resources = links(section('Learning Resources'));
  for (const { label } of KNOWN_HOMES) {
    assert.ok(resources.some((link) => link.label === label), `"Learning Resources" has no [${label}] link`);
  }
  const offenders = links(readme).filter(wrongHome).map(({ label, href }) => `[${label}](${href})`);
  assert.deepEqual(offenders, [], 'links to a known resource that do not point at its home');
});

test('the README gives no wrong address for a known resource', () => {
  assert.deepEqual(wrongAddresses(readme), [], 'resources named at an address they are not at');
});

test('the home check flags a known resource linked anywhere but its home', () => {
  const oasb = 'https://oasb.ai';
  const matrix = 'https://github.com/opena2a-standards/agent-threat-matrix';
  const flagged = [
    { label: 'OASB Standard', href: 'https://oasb.org' },
    { label: 'OASB Standard', href: 'http://oasb.ai' },
    { label: 'OASB Standard', href: 'https://oasb.ai.evil.example' },
    { label: 'OASB Standard', href: matrix },
    { label: 'Agent Threat Matrix', href: 'https://github.com/opena2a-org/agent-threat-matrix' },
    { label: 'Agent Threat Matrix', href: oasb },
  ];
  const notFlagged = flagged.filter((link) => !wrongHome(link));
  assert.deepEqual(notFlagged, [], 'links that miss the home of a known resource but are not flagged');
  const matching = [
    { label: 'OASB Standard', href: oasb },
    { label: 'Agent Threat Matrix', href: matrix },
    // A label that names no known resource is not checked here.
    { label: 'MCP Security Fundamentals', href: 'https://agentpwn.com/learn' },
  ];
  const wronglyFlagged = matching.filter((link) => wrongHome(link));
  assert.deepEqual(wronglyFlagged, [], 'links that point at the home of a known resource but are flagged');
});

test('the address check flags a wrong address in a link, a bare URL, an HTML tag or plain text', () => {
  const former = 'https://github.com/opena2a-org/agent-threat-matrix';
  const flagged = [
    '[OASB](https://oasb.org)',
    '[OASB](https://www.oasb.org/stages)',
    '<https://OASB.org>',
    'See oasb.org.',
    `[Agent Threat Matrix](${former})`,
    `[matrix]: ${former}`,
    `<a href="${former}/issues">issues</a>`,
    `${former}.git`,
    'https://www.github.com/OpenA2A-org/Agent-Threat-Matrix',
  ];
  const notFlagged = flagged.filter((text) => wrongAddresses(text).length === 0);
  assert.deepEqual(notFlagged, [], 'texts that hold a wrong address but are not flagged');
  const other = [
    ...KNOWN_HOMES.map(({ label, home }) => `[${label}](${home})`),
    'https://github.com/opena2a-org/hackmyagent',
    // A longer domain or repository name is a different one.
    `${former}-tools`,
    'https://myoasb.org',
    'https://not-oasb.org',
    'https://oasb.org.uk',
    'https://oasb.organic',
  ];
  const wronglyFlagged = other.filter((text) => wrongAddresses(text).length > 0);
  assert.deepEqual(wronglyFlagged, [], 'texts that hold no wrong address but are flagged');
});

// The agentpwn learn page is a single guide to AI agent security with one section per
// attack category, MCP exploitation among them. It has no lessons, exercises or quizzes.
const LEARN_PAGE = 'https://agentpwn.com/learn';
// Words that would present the page as a course.
const COURSE_CLAIM = /\b(?:course|interactive|lessons?|exercises?|quiz(?:zes)?|fundamentals)\b/i;

test('the Learning Resources entry for the agentpwn learn page describes a guide, not a course', () => {
  const entries = section('Learning Resources')
    .split('\n')
    .filter((line) => links(line).some(({ href }) => href === LEARN_PAGE));
  assert.equal(entries.length, 1, `expected one Learning Resources entry linking ${LEARN_PAGE}`);
  const [entry] = entries;
  assert.doesNotMatch(entry, COURSE_CLAIM, `entry describes the page as a course: ${entry}`);
  assert.match(entry, /\bguide\b/i, `entry does not name the page as a guide: ${entry}`);
  assert.match(entry, /\bMCP exploitation\b/i, `entry does not say where the MCP material is: ${entry}`);
});

// mcp-servers.org and agent-docs.io are each one page whose links lead to agentpwn.com
// and which carries a block addressed to AI agents. Neither is a directory of MCP servers
// or a documentation hub. A longer domain is a different one and is not matched.
const SINGLE_TEST_PAGES = /(?<![\w-])(?:mcp-servers\.org|agent-docs\.io)(?!\.?[\w-])/i;

test('Learning Resources does not list mcp-servers.org or agent-docs.io', () => {
  const entries = section('Learning Resources')
    .split('\n')
    .filter((line) => SINGLE_TEST_PAGES.test(line));
  assert.deepEqual(entries, [], 'Learning Resources entries that point at a single test page');
});

test('the single test page check finds the site in a link, a bare URL, an autolink or an HTML tag', () => {
  const flagged = [
    '- [MCP Server Registry](https://mcp-servers.org) -- directory of MCP servers',
    '- [Agent Documentation Hub](https://agent-docs.io/) -- documentation hub',
    'https://www.mcp-servers.org/servers',
    '<https://AGENT-DOCS.IO>',
    '<a href="https://agent-docs.io/context">guides</a>',
    '[docs]: https://agent-docs.io',
    'See mcp-servers.org.',
  ];
  const notFlagged = flagged.filter((text) => !SINGLE_TEST_PAGES.test(text));
  assert.deepEqual(notFlagged, [], 'texts that name a single test page but are not flagged');
  const other = [
    'https://not-mcp-servers.org',
    'https://mcp-servers.org.uk',
    'https://mcp-servers.organic',
    'https://my-agent-docs.io',
    'https://agent-docs.iox',
    'https://github.com/opena2a-org/mcp-security-checklist',
  ];
  const wronglyFlagged = other.filter((text) => SINGLE_TEST_PAGES.test(text));
  assert.deepEqual(wronglyFlagged, [], 'texts that name another site but are flagged');
});

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

// Returns the path of every key in the excerpt that is missing from the full
// configuration at the same path, or holds a different value there. An object in the
// excerpt may leave keys out; any other value, an array included, must be equal.
function excerptMismatches(excerpt, full, path = '') {
  if (!isPlainObject(excerpt)) return isDeepStrictEqual(excerpt, full) ? [] : [path];
  if (!isPlainObject(full)) return [path];
  return Object.keys(excerpt).flatMap((key) => {
    const keyPath = path ? `${path}.${key}` : key;
    return Object.hasOwn(full, key) ? excerptMismatches(excerpt[key], full[key], keyPath) : [keyPath];
  });
}

test('the configuration excerpt in the README is a shortened copy of mcp-audit.json', () => {
  const blocks = [...section('Reference Audit Configuration').matchAll(/^```json\n([\s\S]*?)^```$/gm)];
  assert.equal(blocks.length, 1, 'expected one JSON block under "Reference Audit Configuration"');
  const excerpt = JSON.parse(blocks[0][1]);
  assert.deepEqual(excerptMismatches(excerpt, auditConfig), [], 'excerpt keys that are missing from mcp-audit.json or differ from it');
  // The README says the excerpt keeps every check group.
  assert.deepEqual(Object.keys(excerpt.audit?.checks ?? {}), Object.keys(auditConfig.audit.checks), 'check groups in the excerpt');
});

test('the excerpt check flags keys that are missing, renamed, moved or changed', () => {
  const full = { audit: { target: { url: 'https://a.example' }, checks: { inputValidation: { enabled: true, list: ['a', 'b'] } } } };
  const cases = [
    // The flat form the README once showed, with a string target and an array of checks.
    [{ target: 'https://a.example', checks: ['input-validation'], reportFormat: 'sarif' }, ['target', 'checks', 'reportFormat']],
    [{ audit: { target: 'https://a.example' } }, ['audit.target']],
    [{ audit: { target: { url: 'https://b.example' } } }, ['audit.target.url']],
    [{ audit: { checks: { 'input-validation': { enabled: true } } } }, ['audit.checks.input-validation']],
    [{ audit: { checks: { inputValidation: { enabled: false } } } }, ['audit.checks.inputValidation.enabled']],
    [{ audit: { checks: { inputValidation: { list: ['a'] } } } }, ['audit.checks.inputValidation.list']],
    [{ audit: { checks: { inputValidation: { enabled: { on: true } } } } }, ['audit.checks.inputValidation.enabled']],
  ];
  for (const [excerpt, expected] of cases) {
    assert.deepEqual(excerptMismatches(excerpt, full), expected, JSON.stringify(excerpt));
  }
  assert.deepEqual(excerptMismatches({ audit: { checks: { inputValidation: { enabled: true } } } }, full), []);
});

test('in-page links resolve to a README heading', () => {
  const anchors = new Set([...readme.matchAll(/^#{1,6} (.+)$/gm)].map(([, heading]) => slug(heading)));
  for (const { label, href } of links(readme)) {
    if (href.startsWith('#')) {
      assert.ok(anchors.has(href.slice(1)), `[${label}](${href}) matches no heading`);
    }
  }
});
