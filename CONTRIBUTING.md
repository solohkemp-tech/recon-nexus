# Contributing to RECON//NEXUS

Thanks for improving this open-source toolkit for **authorized** OSINT research and reconnaissance.

## Useful contributions

- Documentation, localization, accessibility and usability enhancements
- Reproducible Python CLI/GUI bug reports
- False-positive reduction and better evidence for findings
- Scope control, network request safety, tests and cross-platform support

## Report an issue

Include Python version, operating system, command (with credentials and sensitive domain names removed), expected behavior, actual behavior, and a minimal reproduction. Never include customer targets, credentials, API tokens or sensitive scan results in public issues.

For vulnerabilities, use the private reporting guidance in [SECURITY.md](SECURITY.md) rather than a public issue.

## Pull requests

1. Describe the problem and how the change addresses it.
2. Keep changes limited in scope and test CLI and GUI behavior where applicable.
3. Do not relax target-authorization checks, remove TLS verification by default, or expand scanning outside explicitly authorized scope.
4. Document any network requests, third-party services, or data privacy implications.

Please use [Issues](https://github.com/solohkemp-tech/recon-nexus/issues) for feature suggestions and constructive feedback. Do not send artificial traffic or Star automation.
