# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in the MCP Security Checklist text, its reference configuration or the configuration's schema, please report it responsibly.

**Do NOT open a public issue for security vulnerabilities.**

### Reporting Process

1. Email: info@opena2a.org
2. Include a description of the vulnerability, reproduction steps, and potential impact
3. We will acknowledge receipt within 48 hours
4. We aim to provide a fix or mitigation within 7 days for critical issues

### Scope

This policy covers:
- The checklist text in `README.md`, including documentation accuracy (security advice that is itself insecure)
- The reference configuration `mcp-audit.json`, including its `secretPatterns` (for example, a pattern that misses a credential format the README says it matches)
- The configuration's schema, `mcp-audit.schema.json`

The repository ships no audit tool or script. The tests under `test/` check the files above.

### Out of Scope

- Vulnerabilities in MCP protocol implementations (report to the MCP project)
- Issues with third-party MCP servers referenced in documentation
- General AI security questions (use [agentpwn.com/learn](https://agentpwn.com/learn) for educational resources)

## Security Testing

We encourage security testing of MCP deployments. For safe, controlled testing environments:

- [agentpwn.com](https://agentpwn.com) -- honeypot environment for testing agent security tools
- [HackMyAgent](https://hackmyagent.com) -- automated agent security scanning

For written guidance, see the security guides for AI tools and MCP servers at [agentpwn.com/tools](https://agentpwn.com/tools).

## Supported Versions

| Version | Supported |
|---|---|
| main branch | Yes |
| Forks | No |

This repository has no tagged releases yet, so `main` is the only supported version. Security fixes land on `main`.

## Acknowledgments

We maintain a list of security researchers who have responsibly disclosed vulnerabilities. If you report a valid issue, we will credit you (with your permission) in our acknowledgments.
