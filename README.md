<div align="center">

# GoVEX

[![](docs/logo_govex.svg)](https://github.com/grokify/govex)

[![Build Status][build-status-svg]][build-status-url]
[![Lint Status][lint-status-svg]][lint-status-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Visualization][viz-svg]][viz-url]
[![License][license-svg]][license-url]

</div>

## Overview

`govex` is a vulerability reporting solution and library to create and share vulnerability reports via a variety of formats including XLSX, CSV, Markdown, and a git repository. It uses its own VEX vulnerability format that other data sources can be converted to. The reports generated can be used interally (e.g. git repo) or distributed externally (e.g. XLSX). Being written in Go, it can also be easily implemented in CI/CD pipelines and workflows.

## Features

1. **Generic Vulnerability Structs:** There is no widely adopted general format for vulnerabilty information across many database and scanning tools. To facilitate interoperability across different data sources, GoVEX provides its own definition of `govex` structs for vulnerabilities. The format used here is prioritized for use cases supported by this package, currently writing tabular and text reports.
1. **Vulnerability Reports:** Reports in XLSX, CSV, or Markdown is supported via conversion of `Vulnerabilities` slice to a [GoCharts `Table`](https://pkg.go.dev/github.com/grokify/gocharts/v2/data/table#Table) via [`Vulnerabilities.Table()`](https://pkg.go.dev/github.com/grokify/govex#Vulnerabilities.Table) with customizable columns.
1. **Vulnerability Reports Website:** Creation of a Markdown website for managing reports across multiple git-based projects with history is available using `SiteWriter`. This currently intended to be used with a git UI, but may have future support for a Docs-as-Code documentation generator such as [MkDocs](https://www.mkdocs.org/).
1. **CI/CD Integration:** The `Cmd` wrappers provide convenient commans that can be integrated into a CI/CD pipeline with proper OS exit codes.

## Code Visualization

1. [GitHub Next Visualization](https://mango-dune-07a8b7110.1.azurestaticapps.net/?repo=grokify%2Fgovex) ([Article](https://githubnext.com/projects/repo-visualization))

## Contributing

1. By contributing to this repository, you agree that your contributions will be licensed under the MIT License.
1. Commits style uses Conventional Commits conventions available here: [https://www.conventionalcommits.org/](https://www.conventionalcommits.org/)

 [build-status-svg]: https://github.com/grokify/govex/workflows/test/badge.svg
 [build-status-url]: https://github.com/grokify/govex/actions/workflows/test.yaml
 [lint-status-svg]: https://github.com/grokify/govex/workflows/lint/badge.svg
 [lint-status-url]: https://github.com/grokify/govex/actions/workflows/lint.yaml
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
