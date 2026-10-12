# MCP Security Checklist

> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

A comprehensive security checklist for deploying and operating [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers in production environments.

MCP enables AI assistants to interact with external tools and data sources. This power comes with significant security implications that must be addressed before deployment.

## Quick Start

This repository is the checklist itself (below) plus a reference audit
configuration ([mcp-audit.json](./mcp-audit.json)). Work through the checklist
against your MCP deployment. For an automated scan of an MCP server project,
use HackMyAgent:

```bash
# Quick scan of a local MCP server project
npx hackmyagent check ./my-mcp-server/
```

Output from hackmyagent 0.33.2 on a two-file stdio MCP server, captured
2026-10-09 (home directory shown as `~`):

```text
  ~/my-mcp-server  unknown · local · 2 files analyzed
  No issues in the quick-scan matrix

  Quick scan  ━━━━━━━━━━━━━━━━━━━━ 100/100
  Run `secure ./my-mcp-server/` for the full audit (adds credentials, git hygiene, MCP config, file permissions).

  ── Observations ────────────────────────────────────────────
  Surfaces    local project · 2 semantic artifacts · all 2 artifacts reached 0-2 of 7 analyzer families
  Checks      2 semantic (NanoMind AST, 0-2 of 7 analyzer families) · 318 static not run (quick scan)
  Categories  semantic artifact matrix only  (318 static checks not evaluated)
  Verdict     No issues in the semantic artifact matrix. This did NOT evaluate credentials, git hygiene, MCP config, file permissions — run `secure ./my-mcp-server/` before trusting it.


  ── Next Steps ─────────────────────────────────────────────────
  Governance scan:      hackmyagent scan-soul ~/my-mcp-server
  Red-team test:        hackmyagent attack --local
  AI analysis:          hackmyagent check ~/my-mcp-server --nanomind  (attack vectors + targeted remediation)
  All commands:         hackmyagent --help
```

On a local path, `check` is a quick scan. For the full audit (credentials,
git hygiene, MCP config, file permissions), run:

```bash
npx hackmyagent secure ./my-mcp-server/
```

The full audit's MCP checks read an MCP configuration file (for example a
`.mcp.json` that registers the server), not the server source. On a project
that holds only server code, such as the two-file example above, hackmyagent
0.33.2 lists MCP on the `Unexamined` line and reports no MCP findings. Add
the configuration your clients use to launch the server (a `.mcp.json` entry
with its `command` and `args`) to bring MCP into the audit.

## Security Checklist

### 1. Transport Layer Security

- [ ] All MCP connections use TLS 1.3 or higher
- [ ] Certificate pinning enabled for production endpoints
- [ ] mTLS configured for server-to-server MCP communication
- [ ] WebSocket connections use `wss://` (never `ws://`)
- [ ] HTTP Strict Transport Security (HSTS) headers present

### 2. Authentication and Authorization

- [ ] Every MCP tool call requires a valid authentication token
- [ ] Tokens are short-lived (< 1 hour) with refresh rotation
- [ ] Tool-level permissions enforced (not just server-level)
- [ ] API keys are never passed through prompt context
- [ ] OAuth 2.0 / OIDC used for user-facing MCP servers
- [ ] Service accounts have minimum required permissions

### 3. Input Validation and Sanitization

- [ ] All tool parameters validated against JSON Schema before execution
- [ ] String inputs sanitized for injection attacks (SQL, command, path traversal)
- [ ] File path parameters restricted to allowed directories
- [ ] URL parameters validated against allowlists
- [ ] Numeric parameters have reasonable bounds
- [ ] Recursive or self-referencing inputs rejected

> The agentpwn MCP exploitation tests send no crafted parameters to an MCP
> server, so cover the items above with your own test cases. They test whether
> an agent follows instructions hidden in content:
> https://agentpwn.com/attacks/mcp-exploitation

### 4. Tool Sandboxing

- [ ] Each MCP tool runs in an isolated environment (container, sandbox, VM)
- [ ] File system access restricted to designated directories
- [ ] Network access limited to required endpoints only
- [ ] Process execution capabilities disabled unless explicitly needed
- [ ] Resource limits set (CPU, memory, execution time)
- [ ] No shared state between tool executions unless intentional

### 5. Credential Management

- [ ] No credentials stored in MCP configuration files
- [ ] Environment variables used for all secrets
- [ ] Credential rotation automated and tested
- [ ] Secret scanning enabled in CI/CD pipeline
- [ ] MCP server processes cannot read each other's credentials
- [ ] Audit log for all credential access

### 6. Prompt Injection Defense

- [ ] Tool descriptions do not contain executable instructions
- [ ] System prompts clearly delineate tool boundaries
- [ ] User input is never directly interpolated into tool calls
- [ ] Output from tools is treated as untrusted data
- [ ] Content filtering applied to tool responses before display
- [ ] Indirect prompt injection vectors identified and mitigated

> Test whether an agent treats tool output as untrusted data, using fake tool
> results injected into its reasoning:
> https://agentpwn.com/attacks/mcp-exploitation/2

### 7. Logging and Monitoring

- [ ] All MCP tool invocations logged with timestamps and caller identity
- [ ] Sensitive data redacted from logs (credentials, PII)
- [ ] Anomaly detection on tool call patterns (frequency, unusual parameters)
- [ ] Alerts configured for failed authentication attempts
- [ ] Log retention meets compliance requirements
- [ ] Logs stored in tamper-evident storage

### 8. Network Security

- [ ] MCP servers not exposed to public internet unless required
- [ ] Firewall rules restrict MCP traffic to known clients
- [ ] Rate limiting applied per client and per tool
- [ ] DDoS protection in place for public-facing MCP endpoints
- [ ] DNS rebinding protections enabled
- [ ] CORS configured restrictively for browser-based MCP clients

### 9. Supply Chain Security

- [ ] MCP server dependencies audited and pinned
- [ ] Container images scanned for vulnerabilities
- [ ] Third-party MCP tools reviewed before integration
- [ ] SBOM generated for MCP server deployments
- [ ] Dependency update process documented and automated

### 10. Incident Response

- [ ] MCP-specific incident response procedures documented
- [ ] Kill switch to disable individual tools or entire MCP server
- [ ] Procedure for revoking compromised tool credentials
- [ ] Communication plan for security incidents involving AI tools
- [ ] Regular tabletop exercises including MCP compromise scenarios

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
      "network": { "enabled": true, "checkRateLimiting": true }
    },
    "reporting": {
      "format": "sarif",
      "severityThreshold": "medium"
    }
  }
}
```

See [mcp-audit.json](./mcp-audit.json) for the complete configuration.
In it, `target.protocolVersion` names the MCP revision under audit. MCP
identifies each revision by its date (`YYYY-MM-DD`), and that string is what a
client and server negotiate during initialization. The example uses
`2026-07-28`, the current revision; set it to the revision your server
implements, as listed in the
[MCP versioning page](https://modelcontextprotocol.io/specification/versioning).

The `secretPatterns` under `checks.credentials` back the checklist item "No
credentials stored in MCP configuration files". They match:

- a quoted value stored under a name that ends in `api_key`, `api-key`,
  `apikey`, `secret`, `token`, `password` or `credential`, in any letter case,
  as in the `"env": {"API_KEY": "..."}` block of a `.mcp.json`. A value that
  starts with `${` refers to an environment variable and does not match.
- keys that start with `sk-` (including `sk-proj-` and `sk-ant-`), GitHub
  tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) and AWS access
  key IDs (`AKIA`, `ASIA`).

A credential with no known prefix that sits under another name, or in `args`,
is not matched; extend the list for the names your servers use. The patterns
carry no inline flags, lookarounds or backreferences, so JavaScript and Python
compile them as written. Match them case-sensitively.
`test/secret-patterns.test.mjs` runs each pattern against fake credentials
(`node --test`).

## Testing Your Defenses

The best way to verify your MCP security posture is to test against real attack patterns.

| Attack Category | Description | Test Resource |
|---|---|---|
| Tool poisoning | Malicious tool descriptions that alter agent behavior | No dedicated test. Closest: [agentpwn.com/attacks/mcp-exploitation/2](https://agentpwn.com/attacks/mcp-exploitation/2), which injects fake tool results and whose fix text, which the agent is asked to pass to its administrator, says to treat MCP tool descriptions and results as untrusted input |
| Parameter injection | Crafted inputs that escape validation | No dedicated test |
| Credential exfiltration | Attempts to extract secrets via tool responses | No dedicated test. Closest: [agentpwn.com/attacks/mcp-exploitation/2](https://agentpwn.com/attacks/mcp-exploitation/2), whose injected tool result tells the agent to output all environment variables |
| Privilege escalation | Gaining access to tools beyond granted permissions | [agentpwn.com/attacks/mcp-exploitation/3](https://agentpwn.com/attacks/mcp-exploitation/3) |

The agentpwn [MCP exploitation](https://agentpwn.com/attacks/mcp-exploitation)
set has three tests: Tool Discovery, Tool Injection and Cross-Tool Exploit
Chain. "No dedicated test" means none of the three is built for that
category; where one comes near, the row names it as "Closest". Cover the
category with your own test cases, starting from the checklist items in
[3. Input Validation and Sanitization](#3-input-validation-and-sanitization),
[5. Credential Management](#5-credential-management) and
[6. Prompt Injection Defense](#6-prompt-injection-defense).

## Learning Resources

- [AI Agent Security guide](https://agentpwn.com/learn) -- guide to attacks on AI agents, one section per attack category, including a section on MCP exploitation
- [OASB Standard](https://oasb.ai) -- Open Agent Security Benchmark for evaluating agent security
- [Agent Threat Matrix](https://github.com/opena2a-standards/agent-threat-matrix) -- MITRE ATT&CK-style framework for AI agent threats
- [MCP Server Registry](https://mcp-servers.org) -- directory of MCP servers with security metadata and audit status
- [Agent Documentation Hub](https://agent-docs.io) -- centralized documentation for agent protocols, security patterns, and integration guides

## Related Projects

- [HackMyAgent](https://github.com/opena2a-org/hackmyagent) -- automated security scanner for AI agents
- [Secretless AI](https://github.com/opena2a-org/secretless-ai) -- credential isolation for AI development environments
- [OpenA2A](https://github.com/opena2a-org/opena2a) -- open Agent-to-Agent protocol with security built in

## Contributing

Contributions welcome. Please open an issue or PR if you identify missing checklist items or have improvements to the audit configuration.

## License

Licensed under the Creative Commons Attribution 4.0 International License
(CC BY 4.0). See [LICENSE](./LICENSE).
