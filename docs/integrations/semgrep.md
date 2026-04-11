# Semgrep Integration

Integration with [Semgrep](https://semgrep.dev/), a fast static analysis tool.

## Installation

```go
import "github.com/grokify/govex/analyzers/semgrep"
```

## Overview

Semgrep is a lightweight static analysis tool that supports multiple languages. The GoVEX integration converts Semgrep JSON output to the GoVEX vulnerability format.

## Supported Features

- CWE mapping
- OWASP mapping
- Severity classification
- Source code location tracking

## Usage

### Parse Semgrep Output

```go
// Run Semgrep with JSON output
// semgrep --config auto --json -o results.json .

// Parse the results
results, err := semgrep.ParseFile("results.json")
if err != nil {
    log.Fatal(err)
}

// Convert to GoVEX vulnerabilities
vulns := results.ToVulnerabilities()
```

### Generate Reports

```go
// Create a report table
table := vulns.Table(govex.TableColumnDefinitionSetSASTSCAReport())

// Export
table.WriteXLSX("semgrep-report.xlsx")
```

## Running Semgrep

### Basic Scan

```bash
semgrep --config auto --json -o results.json .
```

### With Specific Rules

```bash
semgrep --config p/owasp-top-ten --json -o results.json .
```

### CI Integration

```yaml
# GitHub Actions example
- name: Run Semgrep
  run: |
    pip install semgrep
    semgrep --config auto --json -o semgrep.json .

- name: Process Results
  run: |
    govex merge --input semgrep.json --output vulns.json
```

## Field Mapping

| Semgrep Field | GoVEX Field |
|---------------|-------------|
| `check_id` | `ID` |
| `extra.message` | `Title` |
| `extra.severity` | `Severity` |
| `extra.metadata.cwe` | `CWE` |
| `path` | `Location.File` |
| `start.line` | `Location.Line` |

## Related

- [Integrations Overview](index.md)
- [SpotBugs Integration](spotbugs.md)
