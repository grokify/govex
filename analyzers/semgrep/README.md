# Semgrep Analyzer

This package provides Go structs for parsing and working with Semgrep JSON output.

## Overview

Semgrep is a fast, open-source static analysis tool for finding bugs and enforcing code standards. This package defines Go types that represent the JSON output format produced by Semgrep, making it easy to parse and process Semgrep scan results programmatically.

## Usage

```go
package main

import (
    "encoding/json"
    "os"

    "github.com/grokify/govex/analyzers/semgrep"
)

func main() {
    // Read Semgrep JSON output
    data, err := os.ReadFile("semgrep-output.json")
    if err != nil {
        panic(err)
    }

    // Parse into Go struct
    var output semgrep.Output
    if err := json.Unmarshal(data, &output); err != nil {
        panic(err)
    }

    // Process results
    for _, result := range output.Results {
        println("Finding:", result.CheckID)
        println("  File:", result.Path)
        println("  Line:", result.Start.Line)
        println("  Severity:", result.Extra.Severity)
        println("  Message:", result.Extra.Message)
    }
}
```

## Data Structures

### Core Types

- **`Output`** - Top-level structure containing all scan results and metadata
- **`Result`** - Individual security finding or code issue
- **`Position`** - Source code location (line, column, offset)
- **`Extra`** - Additional finding details (message, fix, metadata, severity)

### Metadata Types

- **`Metadata`** - Comprehensive rule metadata including:
  - CWE (Common Weakness Enumeration) identifiers
  - OWASP Top 10 classifications
  - ASVS (Application Security Verification Standard) mappings
  - Technology tags
  - Vulnerability classifications
  - Confidence, likelihood, and impact ratings

- **`ASVS`** - ASVS control information

### Performance Types

- **`Time`** - Performance metrics and profiling data
- **`ProfilingTimes`** - Overall execution timing
- **`ParsingTime`** - Source code parsing performance
- **`ScanningTime`** - Code scanning performance
- **`MatchingTime`** - Rule matching performance
- **`TaintingTime`** - Taint analysis performance

### Other Types

- **`Paths`** - List of scanned file paths
- **`PerFileTime`** - Statistical timing data (mean, standard deviation)
- **`VerySlowStats`** - Performance outlier statistics
- **`Prefiltering`** - Rule prefiltering metrics

## Example JSON Files

Example Semgrep JSON outputs can be found in `cmd/parse/`:

- `semgrep-java.json` - Java security scan results
- `semgrep-owasp-top-ten.json` - OWASP Top 10 focused scan
- `semgrep-security-audit.json` - General security audit results

## Semgrep Output Format

Semgrep JSON output follows this general structure:

```json
{
  "version": "1.144.1",
  "results": [
    {
      "check_id": "rule-identifier",
      "path": "/path/to/file.java",
      "start": {"line": 28, "col": 44, "offset": 896},
      "end": {"line": 28, "col": 49, "offset": 901},
      "extra": {
        "message": "Description of the issue",
        "severity": "ERROR|WARNING|INFO",
        "metadata": {
          "cwe": ["CWE-XXX: Description"],
          "owasp": ["A01:2021 - Category"],
          "confidence": "HIGH|MEDIUM|LOW",
          "likelihood": "HIGH|MEDIUM|LOW",
          "impact": "HIGH|MEDIUM|LOW"
        }
      }
    }
  ],
  "errors": [],
  "paths": {"scanned": [...]},
  "time": {...}
}
```

## References

- [Semgrep Official Documentation](https://semgrep.dev/docs/)
- [Semgrep JSON Output Format](https://semgrep.dev/docs/cli-reference/#json)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [ASVS - Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
