<div align="center">

# RECON//NEXUS — Open-Source OSINT & Recon Toolkit

**Python reconnaissance tools for authorized security research — CLI, desktop GUI and browser search-query explorer.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776ab?logo=python&logoColor=white)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-3.0.0-45c8ff)](cli/nexus.py)
[![License](https://img.shields.io/badge/license-MIT-2ee6a8)](LICENSE)
[![Platform](https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20macOS-111827)](#installation)

**[Try the browser edition](https://solohkemp-tech.github.io/recon-nexus/)** · **[Quick start](#quick-start)** · **[Features](#features)** · **[فارسی](README.fa.md)** · **[Security](SECURITY.md)**

</div>

> [!IMPORTANT]
> **Authorized scope only.** The Python CLI and GUI can send requests to target systems. Perform active tests only on systems you own or are authorized to assess. A status code or path name alone is **not** a confirmed vulnerability.

## Why RECON//NEXUS?

RECON//NEXUS combines common open-source intelligence (OSINT) and reconnaissance workflows into a transparent, locally executable Python project. It's designed for learning, bug bounty research within program scope, and authorized security assessments.

- **Map your scope:** review DNS records, TLS certificate metadata, Certificate Transparency and archived URLs.
- **Understand exposed services:** investigate discovered subdomains and HTTP response security headers.
- **Triage, don't assume:** optional active path probes produce leads that require manual verification.
- **Choose your workflow:** run the terminal CLI, use the Tkinter desktop GUI, or explore research queries without installing Python.
- **No third-party Python packages or API keys for the CLI:** public information providers and targets still require network access.

<a id="features"></a>
## Features

| Capability | What it helps with | Edition |
|---|---|---|
| DNS and DNS-over-HTTPS | Query common DNS record types using public resolvers | CLI / GUI |
| TLS certificates | Review certificate subject, issuer, validity and SAN metadata | CLI / GUI |
| Subdomain discovery | Combine Certificate Transparency data with candidate DNS lookups | CLI / GUI |
| Wayback Machine | Explore historical URLs and archived resources | CLI / GUI |
| HTTP security headers | Highlight potentially missing security controls | CLI / GUI |
| HTTP path probe | Check selected paths within explicitly authorized scope | CLI / GUI |
| Search queries / dorks | Organize queries for external search engines | CLI / GUI / Web |
| Reports | Review and export findings for later triage | CLI / GUI |

**Accuracy warning:** Automated severity scores are investigation hints. HTTP 200, 401 or an administrative-looking URL is not evidence that an application is vulnerable.

<a id="installation"></a>
## Installation

**Requirements:** Python 3.8+. The command-line edition uses Python's standard library; no pip dependencies or API keys are necessary. The GUI uses Tkinter, which may require an OS-level package such as `python3-tk` on Linux.

```bash
git clone https://github.com/solohkemp-tech/recon-nexus.git
cd recon-nexus
python cli/nexus.py --help
```

On Linux/macOS, use `python3` if `python` is not available.

<a id="quick-start"></a>
## Quick start

Replace sample domains with domains you are permitted to research. Even so-called "passive" commands can query external services or contact the target for TLS metadata.

```bash
# Show research queries; this does not run an HTTP scan
python cli/nexus.py dorks example.com

# Query DNS
python cli/nexus.py dns example.com

# Run the research preset (may perform DNS lookups and TLS connections)
python cli/nexus.py passive example.com
```

**Authorized active assessment only:**

```bash
python cli/nexus.py headers your-owned-domain.example
python cli/nexus.py probe your-owned-domain.example
python cli/nexus.py full your-owned-domain.example -o recon-report
```

Active commands request authorization confirmation. The `-o recon-report` option saves a timestamped JSON report; reports may include information that should not be shared publicly.

### Desktop GUI

```bash
python gui/nexus_gui.py
```

The Tkinter GUI includes target input, module controls, findings, logs and report export. A graphical desktop environment is needed.

### Browser edition

**[Launch RECON//NEXUS Web](https://solohkemp-tech.github.io/recon-nexus/)**

The GitHub Pages site is a **static search-query explorer**: browse categorized queries and open them using your chosen search engine. It **does not run the Python DNS, TLS, or HTTP scanning modules in your browser**.

<a id="three-editions"></a>
## Choose an edition

| | Python CLI | Desktop GUI | Web explorer |
|---|---|---|---|
| Python required | Yes | Yes | No |
| DNS/TLS investigation | Yes | Yes | No |
| Active path checks | Yes | Yes | No |
| Search-query explorer | Yes | Yes | Yes |
| Export | JSON report | Report export | Search-query text |
| Source | [cli/nexus.py](cli/nexus.py) | [gui/nexus_gui.py](gui/nexus_gui.py) | [docs/index.html](docs/index.html) |

## Frequently asked questions

**Is RECON//NEXUS a vulnerability scanner?** It is primarily a reconnaissance and triage toolkit. Its findings require context and human verification.

**Can the browser version scan my domain?** No. The browser edition organizes research queries for external search engines; use the Python editions for their documented network modules.

**Is the CLI completely offline?** No. It has no third-party Python package requirement, but DNS, archive, CT and other research functions use network services.

**Does running it send target information to third parties?** Some features query external DNS, Certificate Transparency, archival or search providers. Review authorization and privacy requirements before using them.

## Project structure

```text
recon-nexus/
├── cli/nexus.py          # Python command-line toolkit
├── gui/nexus_gui.py      # Tkinter desktop app
├── docs/index.html       # Static web search-query explorer
├── README.fa.md          # Persian README
├── SECURITY.md           # Reporting and security guidance
└── LICENSE               # MIT license
```

## Contributing

See the [contribution guide](CONTRIBUTING.md) for issue and pull-request guidance.

Share reproducible bug reports, accessibility suggestions, documentation corrections or feature requests in [GitHub Issues](https://github.com/solohkemp-tech/recon-nexus/issues). Please redact private customer data and credentials. For vulnerabilities, follow [SECURITY.md](SECURITY.md) rather than posting exploit details publicly.

**Like this project?** Give it a GitHub **Star** and share a real use case. We value constructive feedback over artificial traffic.

**Maintainer:** [solohkemp-tech](https://github.com/solohkemp-tech) · [Source code](https://github.com/solohkemp-tech/recon-nexus) · MIT License
