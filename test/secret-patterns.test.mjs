// Checks the secretPatterns in mcp-audit.json against fake credentials, and what
// README.md says about where a key has to start.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

const { secretPatterns } = JSON.parse(read('../mcp-audit.json')).audit.checks.credentials;
// An MCP client configuration: two servers store a credential, one refers to a variable.
const sample = read('./fixtures/sample.mcp.json');
const readme = read('../README.md');

// The "Reference Audit Configuration" section of the README, up to the next "## "
// heading, with each run of whitespace as one space.
function auditSection() {
  const start = readme.indexOf('## Reference Audit Configuration\n');
  assert.notEqual(start, -1, 'README has no "## Reference Audit Configuration" section');
  const next = readme.indexOf('\n## ', start + 1);
  return readme.slice(start, next === -1 ? undefined : next).replace(/\s+/g, ' ');
}

// Each pattern is compiled as written, with no flags, so matching is case-sensitive.
function found(text) {
  return secretPatterns.some((pattern) => new RegExp(pattern).test(text));
}

// Every credential below is fake filler put together at run time, so this file holds
// nothing shaped like a real key.
const fake = (length) => 'FAKE'.repeat(length).slice(0, length);

// The ways a configuration file writes a name next to its value.
const SHAPES = {
  'JSON member': (name, value) => `"${name}": "${value}"`,
  'JSON member without spaces': (name, value) => `"${name}":"${value}"`,
  'JSON member with a space before the colon': (name, value) => `"${name}" : "${value}"`,
  'single-quoted member': (name, value) => `'${name}': '${value}'`,
  assignment: (name, value) => `${name} = '${value}'`,
};

// Key formats, by the prefix that identifies them.
const KEYS = {
  'sk-': `sk-${fake(48)}`,
  'sk-proj-': `sk-proj-${fake(40)}_${fake(40)}-${fake(40)}`,
  'sk-ant-api03-': `sk-ant-api03-${fake(46)}-${fake(46)}_${fake(2)}`,
  ghp_: `ghp_${fake(36)}`,
  gho_: `gho_${fake(36)}`,
  ghu_: `ghu_${fake(36)}`,
  ghs_: `ghs_${fake(36)}`,
  ghr_: `ghr_${fake(36)}`,
  github_pat_: `github_pat_${fake(22)}_${fake(59)}`,
  AKIA: `AKIA${fake(16)}`,
  ASIA: `ASIA${fake(16)}`,
};

// A server entry whose env block holds the value under a name no pattern looks for.
function envBlock(value) {
  return JSON.stringify({ mcpServers: { upstream: { command: 'node', env: { UPSTREAM_AUTH: value } } } }, null, 2);
}

test('every pattern compiles in JavaScript as written', () => {
  assert.ok(secretPatterns.length > 0, 'mcp-audit.json lists no secretPatterns');
  const rejected = [];
  for (const pattern of secretPatterns) {
    // No flags, then the two Unicode modes, which accept fewer escapes.
    for (const flags of ['', 'u', 'v']) {
      try {
        new RegExp(pattern, flags);
      } catch (error) {
        rejected.push({ pattern, flags, error: error.message });
      }
    }
  }
  assert.deepEqual(rejected, [], 'patterns JavaScript does not accept');
});

test('a value stored under a credential name is found however the file writes it', () => {
  const names = ['API_KEY', 'GITHUB_TOKEN', 'apiKey', 'api-key', 'DB_PASSWORD', 'CLIENT_SECRET', 'Credential'];
  const missed = [];
  for (const name of names) {
    for (const [shape, write] of Object.entries(SHAPES)) {
      if (!found(`{"env": {${write(name, fake(16))}}}`)) missed.push({ name, shape });
    }
  }
  assert.deepEqual(missed, [], 'stored values that no pattern finds');
});

test('the sample .mcp.json is flagged on the lines that store a credential and no others', () => {
  const flagged = sample.split('\n').map((line) => line.trim()).filter(found);
  assert.deepEqual(flagged, ['"API_KEY": "FAKE-KEY-1234",', '"GITHUB_TOKEN": "not-a-real-token"']);
  // The same file read at once, as written and without its whitespace.
  assert.ok(found(sample), 'the sample file as written is not flagged');
  assert.ok(found(JSON.stringify(JSON.parse(sample))), 'the sample file without whitespace is not flagged');
});

test('a reference to an environment variable is not read as a stored credential', () => {
  const references = ['${API_KEY}', '${API_KEY:-}', '${env:API_KEY}', '${input:apiKey}'];
  const flagged = [];
  for (const reference of references) {
    for (const [shape, write] of Object.entries(SHAPES)) {
      if (found(write('API_KEY', reference))) flagged.push({ reference, shape });
    }
  }
  assert.deepEqual(flagged, [], 'references flagged as stored credentials');
  // A stored value may itself start with a dollar sign.
  assert.ok(found(SHAPES['JSON member']('DB_PASSWORD', `$${fake(12)}`)), 'a value starting with "$" is not flagged');
});

test('a name that only contains a credential word is not flagged', () => {
  // The word has to end the name: these hold settings, not credentials.
  const settings = [
    ['tokenizer', 'cl100k'],
    ['TOKEN_URL', 'https://example.com/oauth/token'],
    ['passwordPolicy', 'strict'],
    ['SECRET_STORE', 'vault'],
    ['command', 'node'],
  ];
  const flagged = settings.filter(([name, value]) => found(SHAPES['JSON member'](name, value)));
  assert.deepEqual(flagged, [], 'settings flagged as stored credentials');
});

test('each key format is found on its own and inside an env block', () => {
  const missed = [];
  for (const [prefix, key] of Object.entries(KEYS)) {
    // On its own the key has no name beside it, so only its prefix can give it away.
    if (!found(key)) missed.push({ prefix, where: 'on its own' });
    if (!found(`Authorization: Bearer ${key}`)) missed.push({ prefix, where: 'in a header argument' });
    if (!found(envBlock(key))) missed.push({ prefix, where: 'in an env block' });
  }
  assert.deepEqual(missed, [], 'key formats that no pattern finds');
});

test('a word that only contains a key prefix is not read as a key', () => {
  // "task-" and "disk-" end in "sk-"; the others lack the case or the length of a key.
  const words = [
    ['task', 'force', 'alpha', 'bravo', 'charlie', 'delta'].join('-'),
    ['disk', 'usage', 'report', 'generator', 'nightly'].join('-'),
    `akia${fake(16).toLowerCase()}`,
    `GHP_${fake(36)}`,
    `ghp_${fake(35)}`,
    `sk-${fake(19)}`,
  ];
  assert.deepEqual(words.filter((word) => found(envBlock(word))), [], 'words flagged as keys');
});

test('a key prefix glued to an ASCII letter, digit or underscore is not read as a key', () => {
  // Every key pattern opens with a word boundary, so a prefix has to start a word.
  const flagged = [];
  for (const [prefix, key] of Object.entries(KEYS)) {
    for (const before of ['x', 'Z', '7', '_']) {
      if (found(envBlock(`${before}${key}`))) flagged.push({ prefix, before });
    }
  }
  assert.deepEqual(flagged, [], 'glued prefixes read as keys');
});

// A Latin letter with an accent, a Cyrillic letter and an Arabic-Indic digit.
const NON_ASCII = ['é', 'д', '٣'];

test('in JavaScript a key glued to a non-ASCII letter or digit is still found', () => {
  // A JavaScript word boundary counts only A-Z, a-z, 0-9 and _ as word characters.
  const missed = [];
  for (const [prefix, key] of Object.entries(KEYS)) {
    for (const before of NON_ASCII) {
      if (!found(envBlock(`${before}${key}`))) missed.push({ prefix, before });
    }
  }
  assert.deepEqual(missed, [], 'keys after a non-ASCII character that no pattern finds');
});

const python = spawnSync('python3', ['-I', '-c', 'pass']);

test(
  'in Python a key glued to a non-ASCII letter or digit is found only with re.ASCII',
  { skip: python.status === 0 ? false : 'python3 is not installed' },
  () => {
    const keyPatterns = secretPatterns.filter((pattern) => pattern.startsWith('\\b'));
    assert.ok(keyPatterns.length > 0, 'mcp-audit.json lists no pattern that opens with a word boundary');
    const texts = Object.values(KEYS).flatMap((key) => NON_ASCII.map((before) => envBlock(`${before}${key}`)));
    const script = [
      'import json, re, sys',
      'data = json.load(sys.stdin)',
      'found = lambda text, flags: any(re.search(p, text, flags) for p in data["patterns"])',
      'print(json.dumps({',
      '  "unicode": [t for t in data["texts"] if found(t, 0)],',
      '  "ascii": [t for t in data["texts"] if not found(t, re.ASCII)],',
      '}))',
    ].join('\n');
    const run = spawnSync('python3', ['-I', '-c', script], {
      input: JSON.stringify({ patterns: keyPatterns, texts }),
      encoding: 'utf8',
    });
    assert.equal(run.status, 0, run.stderr);
    const { unicode, ascii } = JSON.parse(run.stdout);
    assert.deepEqual(unicode, [], 'keys Python finds after a non-ASCII letter or digit');
    assert.deepEqual(ascii, [], 'keys Python misses with re.ASCII');
  },
);

test('a key behind an escape or an encoded character is found in the decoded text only', () => {
  const flagged = [];
  const missed = [];
  for (const [prefix, key] of Object.entries(KEYS)) {
    // As a JSON file writes it, the key follows the "n" of the escape "\n".
    const json = JSON.stringify({ script: `line1\n${key}` });
    // In a URL, it follows the "D" of "%3D", an encoded "=".
    const url = `https://example.com/search?q=${encodeURIComponent(`key=${key}`)}`;
    if (found(json)) flagged.push({ prefix, where: 'after an escape in JSON text' });
    if (found(url)) flagged.push({ prefix, where: 'after an encoded character in a URL' });
    if (!found(JSON.parse(json).script)) missed.push({ prefix, where: 'in the parsed JSON string' });
    if (!found(decodeURIComponent(url))) missed.push({ prefix, where: 'in the decoded URL' });
  }
  assert.deepEqual(flagged, [], 'keys the README says the patterns miss');
  assert.deepEqual(missed, [], 'keys that no pattern finds in the decoded text');
});

test('a key behind an escape is still found when it is stored under a credential name', () => {
  const missed = [];
  for (const [prefix, key] of Object.entries(KEYS)) {
    if (!found(JSON.stringify({ API_KEY: `line1\n${key}` }))) missed.push(prefix);
  }
  assert.deepEqual(missed, [], 'stored keys after an escape that no pattern finds');
});

test('the README says where a key has to start and how to find one that does not', () => {
  const text = auditSection();
  assert.match(
    text,
    /directly follows an ASCII letter, digit or underscore does not match/,
    'the section does not say that a key glued to an ASCII word character is not matched',
  );
  assert.match(
    text,
    /Python's `re` also counts other Unicode letters and digits unless the pattern is compiled with `re\.ASCII`/,
    'the section does not say where Python and JavaScript differ on a word boundary',
  );
  assert.match(
    text,
    /A key that only the prefix patterns can find, one not stored under a credential name, is also missed/,
    'the section does not limit the escape case to keys the prefix patterns alone can find',
  );
  assert.match(text, /`\{"API_KEY":"line1\\nsk-\.\.\."\}`/, 'the section gives no example of a stored key after an escape');
  assert.match(text, /`"line1\\nsk-\.\.\."`/, 'the section gives no example of a key after an escape');
  assert.match(text, /`\?q=key%3Dsk-\.\.\.`/, 'the section gives no example of a key after an encoded character');
  assert.match(text, /on the decoded text/, 'the section does not say to run the patterns on the decoded text');
});
