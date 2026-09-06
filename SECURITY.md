# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.x.x   | :white_check_mark: |
| 2.x.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Email: security@spectreshield.dev (or use GitHub Security Advisories)
3. Include: description, steps to reproduce, potential impact
4. We will acknowledge within 48 hours
5. We will work with you to understand and address the issue

## Security Best Practices

### Running SpectreShield
- Always run as root (required for eBPF)
- Use a dedicated user account
- Restrict API access to trusted networks
- Enable audit logging
- Use TLS for API in production

### eBPF Security
- Verify eBPF program signatures
- Use kernel 5.4+ for best security
- Monitor eBPF program loading
- Review custom eBPF programs before loading

### API Security
- Use authentication tokens
- Enable rate limiting
- Restrict CORS origins
- Use HTTPS in production

## Disclosure Policy
- We follow coordinated disclosure
- We credit reporters (with permission)
- We notify affected users before public disclosure
