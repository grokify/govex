<div align="center">

# GoVEX

[![](docs/logo_govex.svg)](https://github.com/grokify/govex)

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Visualization][viz-svg]][viz-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/grokify/govex/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/grokify/govex/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/grokify/govex/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/grokify/govex/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/grokify/govex/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/grokify/govex/actions/workflows/go-sast-codeql.yaml
 [goreport-svg]: https://goreportcard.com/badge/github.com/grokify/govex
 [goreport-url]: https://goreportcard.com/report/github.com/grokify/govex
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/grokify/govex
 [docs-godoc-url]: https://pkg.go.dev/github.com/grokify/govex
 [viz-svg]: https://img.shields.io/badge/visualizaton-Go-blue.svg
 [viz-url]: https://mango-dune-07a8b7110.1.azurestaticapps.net/?repo=grokify%2Fgovex
 [loc-svg]: https://tokei.rs/b1/github/grokify/govex
 [repo-url]: https://github.com/grokify/govex
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/grokify/govex/blob/master/LICENSE

</div>

## Overview

`govex` is a vulnerability management library and CLI toolkit for creating, consolidating, and sharing vulnerability reports across multiple formats including XLSX, CSV, Markdown, JSON, and git repositories. It uses its own VEX vulnerability format that other data sources can be converted to. The reports generated can be used internally (e.g., git repo) or distributed externally (e.g., XLSX). Being written in Go, it can also be easily implemented in CI/CD pipelines and workflows.

## Features

1. **Generic Vulnerability Structs:** There is no widely adopted general format for vulnerability information across many databases and scanning tools. To facilitate interoperability across different data sources, GoVEX provides its own definition of `govex` structs for vulnerabilities. The format used here is prioritized for use cases supported by this package, currently writing tabular and text reports.
1. **Vulnerability Reports:** Reports in XLSX, CSV, or Markdown are supported via conversion of `Vulnerabilities` slice to a [GoCharts `Table`](https://pkg.go.dev/github.com/grokify/gocharts/v2/data/table#Table) via [`Vulnerabilities.Table()`](https://pkg.go.dev/github.com/grokify/govex#Vulnerabilities.Table) with customizable columns.
1. **Vulnerability Reports Website:** Creation of a Markdown website for managing reports across multiple git-based projects with history is available using `SiteWriter`. This is currently intended to be used with a git UI, but may have future support for a Docs-as-Code documentation generator such as [MkDocs](https://www.mkdocs.org/).
1. **CI/CD Integration:** The `Cmd` wrappers provide convenient commands that can be integrated into a CI/CD pipeline with proper OS exit codes.
1. **SLA Management:** Track remediation SLAs with severity-based policies, compliance checking, and overdue duration calculations.
1. **Reporter Tracking:** Track internal vs. external reporters with filtering and statistics capabilities.
1. **Security Letters:** Generate SLA exception notifications and security hardening notices in Markdown (Pandoc-compatible for DOCX/PDF).

## Packages

| Package | Description |
|---------|-------------|
| `govex` | Core vulnerability structs, filtering, and table generation |
| `severity` | Severity classification, SLA policies, and statistics |
| `letter` | Security notification letter generation (SLA exceptions, hardening notices) |
| `standards/cve20` | CVE 2.0 format support |
| `standards/cvss30` | CVSS 3.0/3.1 scoring |
| `standards/cwe` | Common Weakness Enumeration parsing |
| `standards/csaf` | Common Security Advisory Framework |
| `analyzers/semgrep` | Semgrep SAST tool integration |
| `analyzers/spotbugs` | SpotBugs Java security analysis |
| `feeds/cisakev` | CISA Known Exploited Vulnerabilities catalog |
| `reports/sitewriter` | Markdown website generation for vulnerability tracking |
| `reports/psirtreport` | PSIRT vulnerability report generation |
| `reports/releasebom` | Release BOM manifest generation |
| `reports/poam` | FedRAMP Plan of Action and Milestones |
| `reports/pentest` | Pentest remediation status reports |

## CLI Commands

```bash
# Main govex CLI
govex merge         # Merge JSON vulnerability files
govex homepage      # Write site homepage for vulnerability reports
govex letter        # Generate security notification letters

# Letter subcommands
govex letter generate --input finding.json --output-md letter.md
govex letter generate --type hardening --input notice.json --output-md letter.md
govex letter schema   # Output JSON Schema for AI agent integration
govex letter example  # Output example JSON template (--type sla or --type hardening)
```

## Integrations

| Tool | Description |
|------|-------------|
| [Grype](https://github.com/anchore/grype) | Via [`github.com/grokify/gogrype`](https://github.com/grokify/gogrype) |
| [Semgrep](https://semgrep.dev/) | SAST tool with CWE and OWASP mapping |
| [SpotBugs](https://spotbugs.github.io/) | Java security analysis |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities catalog |
| [NVD](https://nvd.nist.gov/) | NIST National Vulnerability Database |

## Standards Support

| Standard | Description |
|----------|-------------|
| CVE 2.0 | NIST CVE format |
| CVSS 3.0/3.1/4.0 | Vulnerability scoring |
| CWE | Common Weakness Enumeration |
| CSAF | Common Security Advisory Framework |
| OSCAL/POAM | FedRAMP compliance |

## Installation

```bash
go install github.com/grokify/govex/cmd/govex@latest
```

## Documentation

Full documentation is available at: **[grokify.github.io/govex](https://grokify.github.io/govex/)**

## Code Visualization

1. [GitHub Next Visualization](https://mango-dune-07a8b7110.1.azurestaticapps.net/?repo=grokify%2Fgovex) ([Article](https://githubnext.com/projects/repo-visualization))

## Contributing

1. By contributing to this repository, you agree that your contributions will be licensed under the MIT License.
1. Commits style uses Conventional Commits conventions available here: [https://www.conventionalcommits.org/](https://www.conventionalcommits.org/)
