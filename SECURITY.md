# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x (current) | Yes |

## Responsible Disclosure

If you discover a security vulnerability in this project, please report it
responsibly by sending an email to **bataran7@gmail.com** with the subject line:

```
[SECURITY] DLP Scanner — <short description>
```

Please include:
- A description of the vulnerability
- Steps to reproduce it
- The potential impact

Do **not** open a public GitHub issue for security vulnerabilities.
You will receive a response within 48 hours.

## Security Design Principles

This tool was built with the following security guarantees:

- **No raw PII is ever written to disk.** Only masked values appear in reports.
- **No network calls are made.** The scanner runs entirely offline.
- **No external dependencies.** The attack surface is limited to the Python standard library.
- **Generated reports are excluded from version control** via `.gitignore`.
