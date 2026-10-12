// Checks the secretPatterns in mcp-audit.json against fake credentials.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

const { secretPatterns } = JSON.parse(read('../mcp-audit.json')).audit.checks.credentials;
// An MCP client configuration: two servers store a credential, one refers to a variable.
const sample = read('./fixtures/sample.mcp.json');

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
