# PkgInfo Package

The `pkginfo` package provides a small package-identity type and reference datasets of publicly-disclosed compromised npm packages from the "Qix"/Shai-Hulud supply-chain incidents. The datasets are curated from public disclosures so tooling can screen dependency trees against known-bad name/version pairs.

## Installation

```go
import "github.com/grokify/govex/pkginfo"
```

## PkgInfo

A `PkgInfo` identifies a package by name and version:

| Field | Type | Notes |
|-------|------|-------|
| `Name` | `string` | Package name (npm scope included, e.g. `@duckdb/node-api`) |
| `Version` | `string` | Version string |

`String()` renders the pair as `name@version`, returning just the name when the version is empty and an empty string when the name is empty:

```go
pkg := pkginfo.PkgInfo{Name: "chalk", Version: "5.6.1"}
fmt.Println(pkg.String()) // "chalk@5.6.1"
```

## PkgInfos

`PkgInfos` is a `[]PkgInfo` slice type:

| Method | Returns | Notes |
|--------|---------|-------|
| `Sort()` | | Sorts in place by name (ignoring a leading `@` scope prefix), then by version |
| `Strings()` | `[]string` | Renders each entry via `String()`, dropping blanks and condensing/deduping whitespace |

```go
pkgs := pkginfo.PkgInfos{
    {Name: "chalk", Version: "5.6.1"},
    {Name: "@duckdb/node-api", Version: "1.3.3"},
}
pkgs.Sort()
for _, s := range pkgs.Strings() {
    fmt.Println(s)
}
```

## Compromised-Package Datasets

The package exposes reference lists of npm packages implicated in the publicly-disclosed "Qix"/Shai-Hulud compromises. Use them to check dependency manifests against known-bad name/version pairs.

| Function | Returns | Notes |
|----------|---------|-------|
| `NPMQixHackEvenPkgInfosAll()` | `PkgInfos` | Concatenation of the first and second dataset |
| `NPMQixHackEvenPkgInfos()` | `PkgInfos` | First dataset, parsed and sorted |
| `NPMQixHackEvent2()` | `PkgInfos` | Second dataset, parsed |
| `NPMQixHackEventRaw()` | `string` | Raw source text for the first dataset (`name@version` per line) |
| `NPMQixHackEventRaw2()` | `string` | Raw source text for the second dataset (`name : version` per line) |

```go
infos := pkginfo.NPMQixHackEvenPkgInfosAll()
for _, s := range infos.Strings() {
    fmt.Println(s) // e.g. "chalk@5.6.1", "@duckdb/node-api@1.3.3"
}
```

## qixevent CLI

The `pkginfo/cmd/qixevent` command prints the combined compromised-package list. It emits the full `PkgInfos` as JSON, then the deduplicated `name@version` strings as JSON, then one entry per line:

```bash
go run github.com/grokify/govex/pkginfo/cmd/qixevent
```

## Related

- [Core Package](core.md) - Vulnerability types for representing findings
