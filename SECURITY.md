# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in the MCP Security Checklist tooling or audit scripts, please report it responsibly.

**Do NOT open a public issue for security vulnerabilities.**

### Reporting Process

1. Email: security@opena2a.org
2. Include a description of the vulnerability, reproduction steps, and potential impact
3. We will acknowledge receipt within 48 hours
4. We aim to provide a fix or mitigation within 7 days for critical issues

### Scope

This policy covers:
- The `mcp-audit.json` configuration schema and processing
- Any scripts or tooling provided in this repository
- Documentation accuracy (security advice that is itself insecure)

### Out of Scope

- Vulnerabilities in MCP protocol implementations (report to the MCP project)
- Issues with third-party MCP servers referenced in documentation
- General AI security questions (use [agentpwn.com/learn](https://agentpwn.com/learn) for educational resources)

## Security Testing

We encourage security testing of MCP deployments. For safe, controlled testing environments:

- [agentpwn.com](https://agentpwn.com) -- honeypot environment for testing agent security tools
- [agentpwn.com/tools](https://agentpwn.com/tools) -- curated security testing tools for MCP and A2A
- [HackMyAgent](https://hackmyagent.com) -- automated agent security scanning

## Supported Versions

| Version | Supported |
|---|---|
| main branch | Yes |
| Tagged releases | Yes |
| Forks | No |

## Acknowledgments

We maintain a list of security researchers who have responsibly disclosed vulnerabilities. If you report a valid issue, we will credit you (with your permission) in our acknowledgments.
