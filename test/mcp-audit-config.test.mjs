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
    '[mcp-audit.schema.json](./mcp-audit.schema.json) is a JSON Schema (draft 2020-12) for the configuration: every key, its type and its allowed values.',
    'Validate your copy against it to catch a misspelled key or a value of the wrong type; the schema allows a `$schema` key, so the copy can name the schema for an editor that validates JSON.',
    "Draft 2020-12 treats `format` as an annotation unless a validator is set to assert it, so turn format assertion on for the schema's `uri` and `regex` formats to reject a remediation link that is not a URL or a secret pattern that does not compile.",
    '`test/mcp-audit-schema.test.mjs` (`node --test`) validates `mcp-audit.json` and the excerpt above against the schema.',
  ],
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

// Returns the revision that the paragraph naming `target.protocolVersion` says the
// example uses, from its sentence "The example uses `YYYY-MM-DD`".
function exampleRevision(text) {
  const sentence = protocolVersionSentences(text).find((s) => s.startsWith('The example uses '));
  assert.ok(sentence, 'the protocolVersion paragraph does not say which revision the example uses');
  const match = /^The example uses `([^`]+)`/.exec(sentence);
  assert.ok(match, `"${sentence}" does not name the revision in code quotes`);
  return match[1];
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

test('the README names the revision that mcp-audit.json sets in target.protocolVersion', () => {
  const version = config.audit.target.protocolVersion;
  const named = exampleRevision(auditSection());
  assert.equal(
    named,
    version,
    `README.md says the example uses ${named}, but mcp-audit.json sets target.protocolVersion to ${version}`,
  );
});

test('the example revision check reads the revision from the README sentence, not from mcp-audit.json', () => {
  const paragraph = 'In it, `target.protocolVersion` names the MCP revision under audit. The example uses\n`2025-11-25`, an earlier revision.';
  assert.equal(exampleRevision(paragraph), '2025-11-25');
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

// Matches an ending where it ends a paragraph or list item: before a blank line, the next
// list item or the end of the section, where paragraphs() splits them, and not where it is
// inside a paragraph inserted elsewhere in the section. Each of the two alternatives reads
// the white space after the ending once, so a long run of it is read in linear time.
function paragraphEnd(ending) {
  const escaped = ending.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`${escaped}(?=[ \\t]*\\n(?:\\s*\\n|- )|\\s*$)`);
}

// Adds a handshake sentence that uses none of the three word stems to the end of each
// paragraph and list item the section is known to have, and checks that the section check
// flags it there. Each ending is matched to the paragraph or list item it ends, not to its
// place in the list, so that a paragraph inserted elsewhere in the section is left to the
// section check to report.
function checkStemlessKnownParagraph(section) {
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
    'against the schema.',
    'They match:',
    'refers to an environment variable and does not match.',
    'and not in Python.',
    '(`node --test`).',
  ];
  assert.equal(endings.length, SECTION_SENTENCES.length, 'a known paragraph or list item has no ending to add the sentence after');
  for (const ending of endings) {
    const added = section.replace(paragraphEnd(ending), (text) => `${text}\n${connect}`);
    assert.notEqual(added, section, `the section has no paragraph or list item that ends with "${ending}" to add a sentence after`);
    const index = known.findIndex((paragraph) => paragraph.join(' ').endsWith(ending));
    assert.notEqual(index, -1, `no paragraph or list item of the section ends with "${ending}"`);
    const read = sectionSentences(added);
    assert.equal(read.length, known.length, `"${connect}" after "${ending}" is read as a paragraph of its own`);
    assert.equal(
      read[index].join(' '),
      `${known[index].join(' ')} ${connect}`,
      `"${connect}" after "${ending}" is not read as the end of paragraph or list item ${index + 1}`,
    );
    assert.notDeepEqual(read, SECTION_SENTENCES);
  }
}

test('the section check flags a handshake sentence without the three word stems added to a paragraph or list item it knows', () => {
  checkStemlessKnownParagraph(auditSection());
});

test('the known-paragraph stem-less check leaves a paragraph inserted elsewhere in the section to the section check', () => {
  const link = '[MCP versioning page](https://modelcontextprotocol.io/specification/versioning).';
  for (const inserted of [
    'The audit runs each check group in the order listed.',
    'A client and server negotiate the revision during initialization.',
    // A known ending inside the inserted paragraph does not end a paragraph there.
    'The audit lists what They match: below.',
  ]) {
    const section = auditSection().replace(link, `${link}\n\n${inserted}`);
    assert.ok(paragraphs(section).includes(inserted), `"${inserted}" is not read as a paragraph of its own`);
    assert.notDeepEqual(sectionSentences(section), SECTION_SENTENCES);
    assert.doesNotThrow(() => checkStemlessKnownParagraph(section));
  }
});

test('the known-paragraph ending pattern matches an ending before a blank line, a list item or the end of the section', () => {
  const end = paragraphEnd('They match:');
  for (const after of ['', '\n', ' \t', '  \n', '\n  ', '\n\nNext.', ' \n \nNext.', '\n- next']) {
    assert.ok(end.test(`They match:${after}`), `no match before ${JSON.stringify(after)}`);
  }
  for (const after of [' below.', '\nNext.', '  y', '\n-next']) {
    assert.equal(end.test(`They match:${after}`), false, `a match before ${JSON.stringify(after)}`);
  }
});

test('the known-paragraph ending pattern reads a long run of white space in linear time', () => {
  const start = performance.now();
  assert.equal(paragraphEnd('They match:').test(`x They match:${' '.repeat(100000)}y`), false);
  const elapsed = performance.now() - start;
  assert.ok(elapsed < 1000, `took ${Math.round(elapsed)} ms`);
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
