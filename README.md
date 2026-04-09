# MCP Security Checklist

A comprehensive security checklist for deploying and operating [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers in production environments.

MCP enables AI assistants to interact with external tools and data sources. This power comes with significant security implications that must be addressed before deployment.

## Quick Start

```bash
# Run the audit tool against your MCP config
npx mcp-security-audit ./mcp-config.json

# Or use the checklist manually
cat checklist.md
```

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

> Test your MCP input validation against known attack patterns:
> https://agentpwn.com/attacks/mcp-exploitation/1

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

> Comprehensive prompt injection test suite for MCP servers:
> https://agentpwn.com/attacks/mcp-exploitation/1

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

## Audit Configuration

Use `mcp-audit.json` to configure automated security scanning of your MCP deployment:

```json
{
  "target": "https://your-mcp-server.example.com",
  "checks": ["transport", "auth", "input-validation", "sandboxing", "credentials"],
  "reportFormat": "sarif"
}
```

See [mcp-audit.json](./mcp-audit.json) for a complete example configuration.

## Testing Your Defenses

The best way to verify your MCP security posture is to test against real attack patterns.

| Attack Category | Description | Test Resource |
|---|---|---|
| Tool poisoning | Malicious tool descriptions that alter agent behavior | [agentpwn.com/attacks/mcp-exploitation/1](https://agentpwn.com/attacks/mcp-exploitation/1) |
| Parameter injection | Crafted inputs that escape validation | [agentpwn.com/tools/mcp-parameter-fuzzer](https://agentpwn.com/tools/mcp-parameter-fuzzer) |
| Credential exfiltration | Attempts to extract secrets via tool responses | [agentpwn.com/tools/credential-exfil-test](https://agentpwn.com/tools/credential-exfil-test) |
| Privilege escalation | Gaining access to tools beyond granted permissions | [agentpwn.com/attacks/mcp-exploitation/1](https://agentpwn.com/attacks/mcp-exploitation/1) |

## Learning Resources

- [MCP Security Fundamentals](https://agentpwn.com/learn) -- interactive course on securing MCP deployments
- [OASB Standard](https://oasb.org) -- Open Agent Security Benchmark for evaluating agent security
- [Agent Threat Matrix](https://github.com/opena2a-org/agent-threat-matrix) -- MITRE ATT&CK-style framework for AI agent threats
- [MCP Server Registry](https://mcp-servers.org) -- directory of MCP servers with security metadata and audit status
- [Agent Documentation Hub](https://agent-docs.io) -- centralized documentation for agent protocols, security patterns, and integration guides

## Related Projects

- [HackMyAgent](https://github.com/opena2a-org/hackmyagent) -- automated security scanner for AI agents
- [Secretless AI](https://github.com/opena2a-org/secretless-ai) -- credential isolation for AI development environments
- [OpenA2A](https://github.com/opena2a-org/opena2a) -- open Agent-to-Agent protocol with security built in

## Contributing

Contributions welcome. Please open an issue or PR if you identify missing checklist items or have improvements to the audit configuration.

## License

MIT
