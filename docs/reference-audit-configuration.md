# MCP audit reference

The [README](../README.md) links this page for the reference audit
configuration, the full audit of a project that holds only server code, and
the attack categories that have no dedicated test.

## Reference Audit Configuration

`mcp-audit.json` is a reference configuration that enumerates the checks a
thorough MCP audit should automate. It is illustrative, not consumed by a
tool shipped from this repository. This excerpt keeps every check group and
leaves out most of their settings:

```json
{
  "version": "1.0.0",
  "audit": {
    "target": {
      "url": "https://your-mcp-server.example.com",
      "transport": "streamable-http"
    },
    "checks": {
      "transport": { "enabled": true, "requireTls13": true },
      "authentication": { "enabled": true, "requireTokenAuth": true },
      "inputValidation": { "enabled": true, "requireJsonSchemaValidation": true },
      "sandboxing": { "enabled": true, "checkContainerIsolation": true },
      "credentials": { "enabled": true, "scanConfigForSecrets": true },
      "promptInjection": { "enabled": true, "scanToolDescriptions": true },
      "logging": { "enabled": true, "checkAuditLogging": true },
      "network": { "enabled": true, "checkRateLimiting": true },
      "supplyChain": { "enabled": true, "checkPinnedDependencies": true },
      "incidentResponse": { "enabled": true, "checkToolKillSwitch": true }
    },
    "reporting": {
      "format": "sarif",
      "severityThreshold": "medium"
    }
  }
}
```

See [mcp-audit.json](../mcp-audit.json) for the complete configuration.
In it, `target.protocolVersion` names the MCP revision under audit. MCP
identifies each revision by its date (`YYYY-MM-DD`). From `2026-07-28` on,
every request declares that date in its `_meta` field, and over HTTP also in
the `MCP-Protocol-Version` header. In revisions `2025-11-25` and earlier, a
client and server agree on it in the `initialize` handshake. The example uses
`2026-07-28`, the current revision; set it to the revision your server
implements, as listed in the
[MCP versioning page](https://modelcontextprotocol.io/specification/versioning).

[mcp-audit.schema.json](../mcp-audit.schema.json) is a JSON Schema (draft
2020-12) for the configuration: every key, its type and its allowed values.
Validate your copy against it to catch a misspelled key or a value of the
wrong type; the schema allows a `$schema` key, so the copy can name the schema
for an editor that validates JSON. Draft 2020-12 treats `format` as an
annotation unless a validator is set to assert it, so turn format assertion on
for the schema's `uri` and `regex` formats to reject a remediation link that is
not a URL or a secret pattern that does not compile.
`test/mcp-audit-schema.test.mjs` (`node --test`) validates `mcp-audit.json` and
the excerpt above against the schema.

The `secretPatterns` under `checks.credentials` back the checklist item "No
credentials stored in MCP configuration files". They match:

- a quoted value stored under a name that ends in `api_key`, `api-key`,
  `apikey`, `secret`, `token`, `password` or `credential`, in any letter case,
  as in the `"env": {"API_KEY": "..."}` block of a `.mcp.json`. A value that
  starts with `${` refers to an environment variable and does not match.
- keys that start with `sk-` (including `sk-proj-` and `sk-ant-`), GitHub
  tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) and AWS access
  key IDs (`AKIA`, `ASIA`). The prefix has to start a word: a key that directly
  follows an ASCII letter, digit or underscore does not match. This keeps a
  word that only ends in a prefix, such as `task-` or `disk-`, from being read
  as the start of an `sk-` key. Python's `re` also counts other Unicode letters
  and digits unless the pattern is compiled with `re.ASCII`, so a key right
  after `é`, a Cyrillic letter or an Arabic-Indic digit matches in JavaScript
  and not in Python.

A credential with no known prefix that sits under another name, or in `args`,
is not matched; extend the list for the names your servers use. A key that
only the prefix patterns can find, one not stored under a credential name, is
also missed when an escape or an encoded character puts a letter or a digit
right before it: in the file text `"line1\nsk-..."` the key follows the `n` of
`\n`, and in `?q=key%3Dsk-...` it follows the `D` of `%3D`. Under a credential
name the key is still found, as in `{"API_KEY":"line1\nsk-..."}`. To find such
a key, run the patterns on the decoded text: the parsed JSON string or the
decoded URL.
The patterns carry no inline flags, lookarounds or backreferences, so
JavaScript and Python compile them as written. Match them case-sensitively.
`test/secret-patterns.test.mjs` runs each pattern against fake credentials
(`node --test`).

## Full audit of a project that holds only server code

The README's [Quick Start](../README.md#quick-start) scans a two-file stdio
MCP server with `npx hackmyagent check ./my-mcp-server/`. On a project that
holds only server code, such as the two-file example above, hackmyagent
0.33.2 lists MCP on the `Unexamined` line and reports no MCP findings.

## Attack categories with no dedicated test

A row of the README's [Testing Your Defenses](../README.md#testing-your-defenses)
table that says "No dedicated test" names a category that none of the agentpwn
MCP exploitation tests is built for. Cover the category with your own test
cases, starting from the checklist items in
[3. Input Validation and Sanitization](../README.md#3-input-validation-and-sanitization),
[5. Credential Management](../README.md#5-credential-management) and
[6. Prompt Injection Defense](../README.md#6-prompt-injection-defense).
