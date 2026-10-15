// Checks mcp-audit.json, and the excerpt of it in docs/reference-audit-configuration.md, against
// mcp-audit.schema.json.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

const schema = JSON.parse(read('../mcp-audit.schema.json'));
const config = JSON.parse(read('../mcp-audit.json'));
const reference = read('../docs/reference-audit-configuration.md');
const policy = read('../SECURITY.md');

// The repository installs no packages, so the validator below applies the subset of
// draft 2020-12 that the schema uses. A keyword outside both lists fails the first
// test rather than being skipped without notice.
const APPLIED = new Set([
  'type', 'enum', 'required', 'properties', 'additionalProperties', 'items',
  'minItems', 'uniqueItems', 'minimum', 'minLength', 'pattern', 'format', '$ref',
]);
const ANNOTATIONS = new Set(['$schema', '$id', 'title', 'description', '$defs']);
const FORMATS = {
  uri: (value) => URL.canParse(value),
  regex: (value) => {
    try {
      new RegExp(value);
      return true;
    } catch {
      return false;
    }
  },
};

const TYPES = {
  object: (value) => typeof value === 'object' && value !== null && !Array.isArray(value),
  array: Array.isArray,
  string: (value) => typeof value === 'string',
  integer: Number.isInteger,
  number: (value) => typeof value === 'number' && Number.isFinite(value),
  boolean: (value) => typeof value === 'boolean',
  null: (value) => value === null,
};

// Every subschema, so each one's keywords can be checked.
function* subschemas(node) {
  yield node;
  for (const child of Object.values(node.properties ?? {})) yield* subschemas(child);
  for (const child of Object.values(node.$defs ?? {})) yield* subschemas(child);
  if (typeof node.additionalProperties === 'object') yield* subschemas(node.additionalProperties);
  if (node.items) yield* subschemas(node.items);
}

function resolve(ref) {
  assert.match(ref, /^#\/\$defs\/[A-Za-z]+$/, `unsupported $ref ${ref}`);
  const target = schema.$defs[ref.slice('#/$defs/'.length)];
  assert.ok(target, `$ref ${ref} names no definition`);
  return target;
}

// Returns one message per violation, each led by the JSON Pointer of the value.
function validate(value, node = schema, path = '') {
  const at = path || '/';
  const errors = [];
  if (node.$ref) errors.push(...validate(value, resolve(node.$ref), path));
  if (node.type && !TYPES[node.type](value)) {
    return [...errors, `${at}: expected ${node.type}, got ${JSON.stringify(value)}`];
  }
  if (node.enum && !node.enum.some((allowed) => allowed === value)) {
    errors.push(`${at}: ${JSON.stringify(value)} is not one of ${node.enum.join(', ')}`);
  }
  if (typeof value === 'string') {
    if (node.minLength !== undefined && [...value].length < node.minLength) {
      errors.push(`${at}: shorter than ${node.minLength}`);
    }
    if (node.pattern !== undefined && !new RegExp(node.pattern, 'u').test(value)) {
      errors.push(`${at}: does not match ${node.pattern}`);
    }
    if (node.format !== undefined) {
      assert.ok(FORMATS[node.format], `unsupported format ${node.format}`);
      if (!FORMATS[node.format](value)) errors.push(`${at}: not a valid ${node.format}`);
    }
  }
  if (typeof value === 'number' && node.minimum !== undefined && value < node.minimum) {
    errors.push(`${at}: below ${node.minimum}`);
  }
  if (Array.isArray(value)) {
    if (node.minItems !== undefined && value.length < node.minItems) {
      errors.push(`${at}: fewer than ${node.minItems} items`);
    }
    if (node.uniqueItems && new Set(value.map((item) => JSON.stringify(item))).size !== value.length) {
      errors.push(`${at}: items repeat`);
    }
    if (node.items) value.forEach((item, index) => errors.push(...validate(item, node.items, `${path}/${index}`)));
  }
  if (TYPES.object(value)) {
    for (const key of node.required ?? []) {
      if (!Object.hasOwn(value, key)) errors.push(`${at}: missing ${key}`);
    }
    for (const [key, item] of Object.entries(value)) {
      const child = node.properties?.[key] ?? node.additionalProperties;
      if (child === false) errors.push(`${path}/${key}: not allowed here`);
      else if (typeof child === 'object') errors.push(...validate(item, child, `${path}/${key}`));
    }
  }
  return errors;
}

// Returns the path of every key the schema describes that the value does not have.
function describedKeysMissing(node, value, path = '') {
  return Object.entries(node.properties ?? {}).flatMap(([key, child]) => {
    const keyPath = `${path}/${key}`;
    return TYPES.object(value) && Object.hasOwn(value, key) ? describedKeysMissing(child, value[key], keyPath) : [keyPath];
  });
}

// The first JSON block under a heading of the reference page.
function referenceExample(heading) {
  const start = reference.indexOf(`## ${heading}\n`);
  assert.notEqual(start, -1, `the reference page has no "## ${heading}" section`);
  const block = reference.slice(start).match(/```json\n([\s\S]*?)\n```/);
  assert.ok(block, `"## ${heading}" holds no JSON example`);
  return JSON.parse(block[1]);
}

// A file or directory path in code quotes: a name with the extension of a document, a
// configuration or a script, or a name that ends in a slash, after any directory names
// that each end in a slash, such as `test/fixtures/`, and after an optional `./`, as in
// `./test/`. A directory name may start with a dot, as `.github/` does, and has no other dot
// in it, so a domain with a path, such as `agentpwn.com/learn`, is not a file name. Any other
// token with a dot in it is not a file name either, such as the version `1.0.x`, the key
// `checks.credentials` or a domain.
const FILE_NAME = /`((?:\.\/)?(?:(?:\.?[\w-]+\/)*[\w.-]+\.(?:cjs|js|json|md|mjs|py|sh|toml|ts|txt|ya?ml)|(?:\.?[\w-]+\/)+))`/g;
const namedFiles = (text) => [...text.matchAll(FILE_NAME)].map(([, path]) => path);

test('the schema is draft 2020-12 and uses only keywords this validator applies', () => {
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  for (const node of subschemas(schema)) {
    for (const keyword of Object.keys(node)) {
      assert.ok(APPLIED.has(keyword) || ANNOTATIONS.has(keyword), `keyword ${keyword} is not applied`);
    }
    if (node.type) assert.ok(TYPES[node.type], `unsupported type ${node.type}`);
    if (node.format) assert.ok(FORMATS[node.format], `unsupported format ${node.format}`);
    if (node.$ref) resolve(node.$ref);
  }
});

test('mcp-audit.json matches the schema', () => {
  assert.deepEqual(validate(config), []);
});

// With the test above, this keeps the schema and the configuration key for key: a key
// renamed or removed in mcp-audit.json has to be renamed or removed here too.
test('the schema describes no key that mcp-audit.json lacks, other than $schema', () => {
  assert.deepEqual(describedKeysMissing(schema, config), ['/$schema']);
});

test('the configuration excerpt in docs/reference-audit-configuration.md matches the schema', () => {
  assert.deepEqual(validate(referenceExample('Reference Audit Configuration')), []);
});

test('the schema rejects a configuration with a mistake in it', () => {
  const MISTAKES = {
    'a misspelled key': [(copy) => {
      copy.audit.checks.transport.requireTLS13 = true;
    }, '/audit/checks/transport/requireTLS13: not allowed here'],
    'a check group under an unknown name': [(copy) => {
      copy.audit.checks.auth = { enabled: true };
    }, '/audit/checks/auth: not allowed here'],
    'a number written as a string': [(copy) => {
      copy.audit.checks.authentication.maxTokenLifetimeSeconds = '3600';
    }, '/audit/checks/authentication/maxTokenLifetimeSeconds: expected integer, got "3600"'],
    'a fractional limit': [(copy) => {
      copy.audit.checks.sandboxing.maxMemoryMb = 0.5;
    }, '/audit/checks/sandboxing/maxMemoryMb: expected integer, got 0.5'],
    'a zero limit': [(copy) => {
      copy.audit.checks.network.maxRequestsPerMinute = 0;
    }, '/audit/checks/network/maxRequestsPerMinute: below 1'],
    'a check group without enabled': [(copy) => {
      delete copy.audit.checks.logging.enabled;
    }, '/audit/checks/logging: missing enabled'],
    'no version': [(copy) => {
      delete copy.version;
    }, '/: missing version'],
    'a version that is not MAJOR.MINOR.PATCH': [(copy) => {
      copy.version = '1';
    }, '/version: does not match ^[0-9]+\\.[0-9]+\\.[0-9]+$'],
    'a target that is not an HTTP URL': [(copy) => {
      copy.audit.target.url = 'ftp://your-mcp-server.example.com';
    }, '/audit/target/url: does not match ^https?://'],
    'a protocol version that is not a dated revision': [(copy) => {
      copy.audit.target.protocolVersion = 'mcp-v1';
    }, '/audit/target/protocolVersion: does not match ^[0-9]{4}-[0-9]{2}-[0-9]{2}$'],
    'a version label under protocol': [(copy) => {
      copy.audit.target.protocol = 'mcp-v1';
    }, '/audit/target/protocol: not allowed here'],
    'a transport the configuration does not cover': [(copy) => {
      copy.audit.target.transport = 'stdio';
    }, '/audit/target/transport: "stdio" is not one of streamable-http, sse'],
    'a secret pattern that does not compile': [(copy) => {
      copy.audit.checks.credentials.secretPatterns = ['(unclosed'];
    }, '/audit/checks/credentials/secretPatterns/0: not a valid regex'],
    'no secret patterns': [(copy) => {
      copy.audit.checks.credentials.secretPatterns = [];
    }, '/audit/checks/credentials/secretPatterns: fewer than 1 items'],
    'a repeated log field': [(copy) => {
      copy.audit.checks.logging.requiredLogFields.push('timestamp');
    }, '/audit/checks/logging/requiredLogFields: items repeat'],
    'an unknown severity': [(copy) => {
      copy.audit.reporting.severityThreshold = 'severe';
    }, '/audit/reporting/severityThreshold: "severe" is not one of info, low, medium, high, critical'],
    'a remediation link that is not a URL': [(copy) => {
      copy.audit.reporting.remediationResources.toolSecurityGuides = 'agentpwn tools';
    }, '/audit/reporting/remediationResources/toolSecurityGuides: not a valid uri'],
  };
  for (const [name, [mistake, message]] of Object.entries(MISTAKES)) {
    const copy = structuredClone(config);
    mistake(copy);
    assert.deepEqual(validate(copy), [message], name);
  }
});

test('every file the security policy names is in the repository', () => {
  const named = namedFiles(policy);
  assert.ok(named.includes('mcp-audit.schema.json'), 'SECURITY.md does not name the schema');
  for (const path of named) {
    assert.ok(existsSync(new URL(`../${path}`, import.meta.url)), `SECURITY.md names ${path}, which does not exist`);
  }
});

test('the file-name check reads a version, a configuration key or a domain in code quotes as no file name', () => {
  assert.deepEqual(namedFiles('`README.md`, `mcp-audit.schema.json`, `audit.sh`, `scan.py`, `ci.yml` and `test/`'), [
    'README.md', 'mcp-audit.schema.json', 'audit.sh', 'scan.py', 'ci.yml', 'test/',
  ]);
  // Each of these has a dot and a lowercase suffix, and is not a file.
  assert.deepEqual(namedFiles('`1.0.x`, `checks.credentials`, `target.url`, `agentpwn.com` and `main`'), []);
  // The security policy with a version range added to it still names only files that exist.
  const missing = namedFiles(`${policy}\nVersions \`1.0.x\` receive security fixes.\n`)
    .filter((path) => !existsSync(new URL(`../${path}`, import.meta.url)));
  assert.deepEqual(missing, []);
});

test('the file-name check reads a code-quoted path with a directory in it as a file name', () => {
  assert.deepEqual(namedFiles('`test/missing.mjs`, `test/fixtures/` and `.github/workflows/ci.yml`'), [
    'test/missing.mjs', 'test/fixtures/', '.github/workflows/ci.yml',
  ]);
  // A domain with a path is not a file name.
  assert.deepEqual(namedFiles('`agentpwn.com/learn`, `agentpwn.com/tools/` and `example.com/install.sh`'), []);
  // The security policy with a missing file named by its directory names that file.
  const missing = namedFiles(`${policy}\nThe tests run \`test/missing.mjs\`.\n`)
    .filter((path) => !existsSync(new URL(`../${path}`, import.meta.url)));
  assert.deepEqual(missing, ['test/missing.mjs']);
});

test('the file-name check reads a code-quoted path that starts with ./ as a file name', () => {
  assert.deepEqual(namedFiles('`./test/missing.mjs`, `./mcp-audit.json` and `./test/`'), [
    './test/missing.mjs', './mcp-audit.json', './test/',
  ]);
  // A domain with a path is not a file name with ./ in front of it either.
  assert.deepEqual(namedFiles('`./agentpwn.com/learn` and `./agentpwn.com/tools/`'), []);
  // The security policy with a missing file named from the current directory names that file,
  // and a file or directory that exists, named the same way, is found.
  const missing = namedFiles(`${policy}\nThe tests run \`./test/missing.mjs\` on \`./mcp-audit.json\` in \`./test/\`.\n`)
    .filter((path) => !existsSync(new URL(`../${path}`, import.meta.url)));
  assert.deepEqual(missing, ['./test/missing.mjs']);
});

test('docs/reference-audit-configuration.md names each format the schema uses and says a validator has to assert it', () => {
  const formats = new Set([...subschemas(schema)].flatMap(({ format }) => (typeof format === 'string' ? [format] : [])));
  assert.notEqual(formats.size, 0, 'the schema uses no format');
  const sentence = reference.replace(/\s+/g, ' ').split(/(?<=\.) /).find((text) => text.includes('format assertion'));
  assert.ok(sentence, 'the reference page does not say that a format holds only under format assertion');
  assert.match(sentence, /`format`/, `does not name the keyword: ${sentence}`);
  assert.match(sentence, /\bannotation\b/, `does not say a format is an annotation by default: ${sentence}`);
  for (const format of formats) {
    assert.ok(sentence.includes(`\`${format}\``), `does not name the ${format} format: ${sentence}`);
  }
});
