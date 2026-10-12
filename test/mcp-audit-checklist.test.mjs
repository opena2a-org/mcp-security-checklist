// Checks that mcp-audit.json covers the "Security Checklist" in README.md.
// Run from the repository root: node --test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const config = JSON.parse(readFileSync(new URL('../mcp-audit.json', import.meta.url), 'utf8'));
const checks = config.audit.checks;

// The check group in mcp-audit.json for each numbered checklist section, in README order.
const GROUP_FOR_SECTION = {
  'Transport Layer Security': 'transport',
  'Authentication and Authorization': 'authentication',
  'Input Validation and Sanitization': 'inputValidation',
  'Tool Sandboxing': 'sandboxing',
  'Credential Management': 'credentials',
  'Prompt Injection Defense': 'promptInjection',
  'Logging and Monitoring': 'logging',
  'Network Security': 'network',
  'Supply Chain Security': 'supplyChain',
  'Incident Response': 'incidentResponse',
};

function section(heading) {
  const start = readme.indexOf(`## ${heading}\n`);
  assert.notEqual(start, -1, `README has no "## ${heading}" section`);
  const next = readme.indexOf('\n## ', start + 1);
  return readme.slice(start, next === -1 ? undefined : next);
}

const checklist = section('Security Checklist');
const checklistSections = [...checklist.matchAll(/^### \d+\. (.+)$/gm)].map(([, heading]) => heading);

test('every checklist section has a check group, and every check group a checklist section', () => {
  assert.deepEqual(checklistSections, Object.keys(GROUP_FOR_SECTION), 'README checklist sections differ from the mapping in this test');
  assert.deepEqual(Object.keys(checks), Object.values(GROUP_FOR_SECTION), 'mcp-audit.json check groups differ from the checklist sections');
});

test('every check group is enabled', () => {
  const disabled = Object.entries(checks).filter(([, group]) => group.enabled !== true).map(([name]) => name);
  assert.deepEqual(disabled, [], 'check groups that are not enabled');
});

test('every on/off option defaults to on, as the checklist asks for each item', () => {
  const off = Object.entries(checks).flatMap(([name, group]) =>
    Object.entries(group).filter(([, value]) => value === false).map(([option]) => `${name}.${option}`));
  assert.deepEqual(off, [], 'options that default to off');
});

test('transport requires the certificate pinning the checklist lists', () => {
  assert.match(checklist, /^- \[ \] Certificate pinning enabled for production endpoints$/m);
  assert.equal(checks.transport.certificatePinning, true);
});

test('authentication requires the server-to-server mTLS the checklist lists', () => {
  assert.match(checklist, /^- \[ \] mTLS configured for server-to-server MCP communication$/m);
  assert.equal(checks.authentication.requireMtlsForServerToServer, true);
});

test('supply chain checks cover pinned dependencies, image scanning and an SBOM', () => {
  for (const option of ['checkPinnedDependencies', 'scanContainerImages', 'requireSbom']) {
    assert.equal(checks.supplyChain?.[option], true, `supplyChain.${option}`);
  }
});

test('incident response checks cover the tool and server kill switch', () => {
  for (const option of ['checkToolKillSwitch', 'checkServerKillSwitch']) {
    assert.equal(checks.incidentResponse?.[option], true, `incidentResponse.${option}`);
  }
});
