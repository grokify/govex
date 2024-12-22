# GoVEX

[![Build Status][build-status-svg]][build-status-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![LOC][loc-svg]][repo-url]
[![License][license-svg]][license-url]

`govex` is a Go package with various VEX helpers, including:

1. Definition of `govex` structs for vulnerabilities.
1. Conversion of `Vulnerabilities` slice to a [GoCharts `Table`](https://pkg.go.dev/github.com/grokify/gocharts/v2/data/table#Table) via [`Vulnerabilities.Table()`](https://pkg.go.dev/github.com/grokify/govex#Vulnerabilities.Table) with customizable columns. This can then be exported as a CSV or XLSX file.

## Contributing

1. Commits are prefixed with Conventional Commits conventions available here: [https://www.conventionalcommits.org/](https://www.conventionalcommits.org/)

 [build-status-svg]: https://github.com/grokify/govex/workflows/test/badge.svg
 [build-status-url]: https://github.com/grokify/govex/actions/workflows/test.yaml
 [goreport-svg]: https://goreportcard.com/badge/github.com/grokify/govex
 [goreport-url]: https://goreportcard.com/report/github.com/grokify/govex
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/grokify/govex
 [docs-godoc-url]: https://pkg.go.dev/github.com/grokify/govex
 [loc-svg]: https://tokei.rs/b1/github/grokify/govex
 [repo-url]: https://github.com/grokify/govex
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/grokify/govex/blob/master/LICENSE
