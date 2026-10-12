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

// A sentence that names the handshake with one of three word stems: "initiali[sz]"
// (initialize, initialization), "handshake" or "negotiat" (negotiate, negotiation).
// A sentence that says the same in other words, such as "they agree on it when they
// connect", does not match; the section check below catches one wherever it is added,
// in a paragraph or list item the section is known to have or in one of its own.
const HANDSHAKE = /initiali[sz]|handshake|negotiat/i;
// The scope such a sentence has to carry: the last revision that has the handshake,
// with or without code quotes, "and earlier".
const HANDSHAKE_SCOPE = new RegExp(`\`?${LAST_HANDSHAKE_REVISION}\`? and earlier`);

// The README paragraph that explains target.protocolVersion, sentence by sentence. It is
// compared whole because the handshake filter above misses a sentence that uses none of
// its three word stems.
const PROTOCOL_VERSION_SENTENCES = [
  'See [mcp-audit.json](./mcp-audit.json) for the complete configuration.',
  'In it, `target.protocolVersion` names the MCP revision under audit.',
  'MCP identifies each revision by its date (`YYYY-MM-DD`).',
  'From `2026-07-28` on, every request declares that date in its `_meta` field, and over HTTP also in the `MCP-Protocol-Version` header.',
  'In revisions `2025-11-25` and earlier, a client and server agree on it in the `initialize` handshake.',
  'The example uses `2026-07-28`, the current revision; set it to the revision your server implements, as listed in the [MCP versioning page](https://modelcontextprotocol.io/specification/versioning).',
];

// Each paragraph and list item of the section, in order and sentence by sentence. Each is
// compared whole: a sentence added to one of them, such as a handshake sentence that uses
// none of the three word stems, fails the section check, and so does a paragraph or list
// item that is not on this list.
const SECTION_SENTENCES = [
  [
    '`mcp-audit.json` is a reference configuration that enumerates the checks a thorough MCP audit should automate.',
    'It is illustrative, not consumed by a tool shipped from this repository.',
    'This excerpt keeps every check group and leaves out most of their settings:',
  ],
  PROTOCOL_VERSION_SENTENCES,
  [
    'The `secretPatterns` under `checks.credentials` back the checklist item "No credentials stored in MCP configuration files".',
    'They match:',
  ],
  [
    '- a quoted value stored under a name that ends in `api_key`, `api-key`, `apikey`, `secret`, `token`, `password` or `credential`, in any letter case, as in the `"env": {"API_KEY": "..."}` block of a `.mcp.json`.',
    'A value that starts with `${` refers to an environment variable and does not match.',
  ],
  [
    '- keys that start with `sk-` (including `sk-proj-` and `sk-ant-`), GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) and AWS access key IDs (`AKIA`, `ASIA`).',
    'The prefix has to start a word: a key that directly follows an ASCII letter, digit or underscore does not match.',
    'This keeps a word that only ends in a prefix, such as `task-` or `disk-`, from being read as the start of an `sk-` key.',
    "Python's `re` also counts other Unicode letters and digits unless the pattern is compiled with `re.ASCII`, so a key right after `é`, a Cyrillic letter or an Arabic-Indic digit matches in JavaScript and not in Python.",
  ],
  [
    'A credential with no known prefix that sits under another name, or in `args`, is not matched; extend the list for the names your servers use.',
    'A key that only the prefix patterns can find, one not stored under a credential name, is also missed when an escape or an encoded character puts a letter or a digit right before it: in the file text `"line1\\nsk-..."` the key follows the `n` of `\\n`, and in `?q=key%3Dsk-...` it follows the `D` of `%3D`.',
    'Under a credential name the key is still found, as in `{"API_KEY":"line1\\nsk-..."}`.',
    'To find such a key, run the patterns on the decoded text: the parsed JSON string or the decoded URL.',
    'The patterns carry no inline flags, lookarounds or backreferences, so JavaScript and Python compile them as written.',
    'Match them case-sensitively.',
    '`test/secret-patterns.test.mjs` runs each pattern against fake credentials (`node --test`).',
  ],
];

function sentences(text) {
  return text.replace(/\s+/g, ' ').trim().split(/(?<=\.) /);
}

// The paragraphs and list items of the section, each on one line, without its code blocks
// and without its "## " heading when the text starts with one. A first line that is not a
// heading is kept, so that text without a heading loses none of its sentences.
function paragraphs(text) {
  return text
    .replace(/^## .*\n?/, '')
    .replace(/^```[\s\S]*?^```$/gm, '')
    .split(/\n\s*\n|\n(?=- )/)
    .map((block) => block.replace(/\s+/g, ' ').trim())
    .filter(Boolean);
}

// Returns the sentences of each paragraph and list item of the section.
function sectionSentences(text) {
  return paragraphs(text).map((paragraph) => sentences(paragraph));
}

// Returns the sentences about the handshake that do not limit it to the last revision
// that has one and the revisions before it, so that they read as true of every revision
// or of the wrong ones.
function unscopedHandshakeSentences(text) {
  return sentences(text).filter((sentence) => HANDSHAKE.test(sentence) && !HANDSHAKE_SCOPE.test(sentence));
}

// Returns the sentences of the paragraph that names `target.protocolVersion`.
function protocolVersionSentences(text) {
  const paragraph = paragraphs(text).find((block) => block.includes('`target.protocolVersion`'));
  assert.ok(paragraph, 'the section has no paragraph that names `target.protocolVersion`');
  return sentences(paragraph);
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

test('the README protocolVersion paragraph says how each revision carries its version, and nothing more', () => {
  assert.deepEqual(protocolVersionSentences(auditSection()), PROTOCOL_VERSION_SENTENCES);
});

// Adds a handshake sentence that uses none of the three word stems to the protocolVersion
// paragraph of the section, and checks that the paragraph check flags it and the handshake
// filter does not. The filter is tested on the added sentence alone, so that an unscoped
// handshake sentence elsewhere in the section is left to the handshake check to report.
function checkStemlessHandshakeSentence(section) {
  const connect = 'A client and server agree on it when they connect.';
  const added = section.replace('`initialize` handshake.', `\`initialize\` handshake. ${connect}`);
  assert.notEqual(added, section, 'the section has no "`initialize` handshake." to add a sentence after');
  assert.equal(
    HANDSHAKE.test(connect),
    false,
    'the handshake filter now matches a sentence without its three word stems; update the HANDSHAKE comment',
  );
  assert.ok(protocolVersionSentences(added).includes(connect));
  assert.notDeepEqual(protocolVersionSentences(added), PROTOCOL_VERSION_SENTENCES);
}

test('the paragraph check flags a handshake sentence that uses none of the three word stems', () => {
  checkStemlessHandshakeSentence(auditSection());
});

test('the stem-less sentence check leaves an unscoped handshake sentence elsewhere in the section to the handshake check', () => {
  const unscoped = 'A client and server negotiate the revision during initialization.';
  const section = `${auditSection()}\n\n${unscoped}\n`;
  assert.ok(unscopedHandshakeSentences(section).includes(unscoped));
  assert.doesNotThrow(() => checkStemlessHandshakeSentence(section));
});

test('the paragraph split drops a first line only when it is the section heading', () => {
  const sentence = 'In it, `target.protocolVersion` names the MCP revision under audit.';
  assert.deepEqual(protocolVersionSentences(`${sentence}\nMore.`), [sentence, 'More.']);
  assert.deepEqual(paragraphs(`## Reference Audit Configuration\n${sentence}`), [sentence]);
});

test('the README section has only the paragraphs, list items and sentences it is known to have', () => {
  assert.deepEqual(sectionSentences(auditSection()), SECTION_SENTENCES);
});

// Adds a handshake sentence that uses none of the three word stems to the section, as a
// paragraph and as a list item of its own, and checks that the section check flags it and
// the handshake filter does not. The filter is tested on the added sentence alone, so that
// an unscoped handshake sentence elsewhere in the section is left to the handshake check
// to report.
function checkStemlessHandshakeParagraph(section) {
  const connect = 'A client and server agree on it when they connect.';
  const link = '[MCP versioning page](https://modelcontextprotocol.io/specification/versioning).';
  const credential = '\n\nA credential with no known prefix';
  const additions = [
    // A paragraph after the protocolVersion paragraph.
    { anchor: link, replacement: `${link}\n\n${connect}`, paragraph: connect },
    // A third item in the list of what the secretPatterns match.
    { anchor: credential, replacement: `\n- ${connect}${credential}`, paragraph: `- ${connect}` },
  ];
  assert.equal(
    HANDSHAKE.test(connect),
    false,
    'the handshake filter now matches a sentence without its three word stems; update the HANDSHAKE comment',
  );
  for (const { anchor, replacement, paragraph } of additions) {
    const added = section.replace(anchor, replacement);
    assert.notEqual(added, section, `the section has no "${anchor.trim()}" to add a paragraph next to`);
    assert.deepEqual(protocolVersionSentences(added), PROTOCOL_VERSION_SENTENCES);
    assert.ok(paragraphs(added).includes(paragraph), `"${paragraph}" is not read as a paragraph of its own`);
    assert.notDeepEqual(sectionSentences(added), SECTION_SENTENCES);
  }
}

test('the section check flags a handshake sentence without the three word stems in a paragraph or list item of its own', () => {
  checkStemlessHandshakeParagraph(auditSection());
});

test('the stem-less paragraph check leaves an unscoped handshake sentence elsewhere in the section to the handshake check', () => {
  const unscoped = 'A client and server negotiate the revision during initialization.';
  const link = '[MCP versioning page](https://modelcontextprotocol.io/specification/versioning).';
  const section = auditSection().replace(link, `${link}\n\n${unscoped}`);
  assert.ok(unscopedHandshakeSentences(section).includes(unscoped));
  assert.doesNotThrow(() => checkStemlessHandshakeParagraph(section));
});

test('the section check flags a handshake sentence without the three word stems added to a paragraph or list item it knows', () => {
  const section = auditSection();
  const known = sectionSentences(section);
  const connect = 'A client and server agree on it when they connect.';
  assert.equal(
    HANDSHAKE.test(connect),
    false,
    'the handshake filter now matches a sentence without its three word stems; update the HANDSHAKE comment',
  );
  // How each paragraph and list item of the section ends in the README, in order. The
  // sentence is added on a new line after each.
  const endings = [
    'leaves out most of their settings:',
    '[MCP versioning page](https://modelcontextprotocol.io/specification/versioning).',
    'They match:',
    'refers to an environment variable and does not match.',
    'and not in Python.',
    '(`node --test`).',
  ];
  assert.equal(endings.length, SECTION_SENTENCES.length, 'a known paragraph or list item has no ending to add the sentence after');
  endings.forEach((ending, index) => {
    const added = section.replace(ending, `${ending}\n${connect}`);
    assert.notEqual(added, section, `the section has no "${ending}" to add a sentence after`);
    const read = sectionSentences(added);
    assert.equal(read.length, known.length, `"${connect}" after "${ending}" is read as a paragraph of its own`);
    assert.equal(
      read[index].join(' '),
      `${known[index].join(' ')} ${connect}`,
      `"${connect}" after "${ending}" is not read as the end of paragraph or list item ${index + 1}`,
    );
    assert.notDeepEqual(read, SECTION_SENTENCES);
  });
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
