# GoVEX

**Vulnerability management library and CLI toolkit for Go**

GoVEX is a comprehensive solution for creating, consolidating, and sharing vulnerability reports across multiple formats including XLSX, CSV, Markdown, JSON, and git repositories.

## Features

- **Generic Vulnerability Structs** - Unified format for vulnerability data from various sources
- **Multi-Format Reports** - Generate XLSX, CSV, and Markdown reports
- **Vulnerability Website** - Create Markdown websites for tracking vulnerabilities across projects
- **CI/CD Integration** - Commands with proper exit codes for pipeline integration
- **SLA Management** - Track remediation SLAs with severity-based policies
- **Security Letters** - Generate SLA exception and hardening notification letters

## Quick Example

```go
import "github.com/grokify/govex"

// Create a vulnerability set
vulns := govex.Vulnerabilities{
    {
        ID:       "CVE-2024-1234",
        Title:    "SQL Injection in login form",
        Severity: "High",
        Status:   "Open",
    },
}

// Generate a table for reporting
table := vulns.Table(govex.TableColumnDefinitionSetSASTSCAReport())

// Export to XLSX
table.WriteXLSX("vulnerabilities.xlsx")
```

## Packages

| Package | Description |
|---------|-------------|
| `govex` | Core vulnerability structs, filtering, and table generation |
| `severity` | Severity classification, SLA policies, and statistics |
| `letter` | Security notification letter generation |
| `analyzers/semgrep` | Semgrep SAST integration |
| `analyzers/spotbugs` | SpotBugs Java analysis |
| `feeds/cisakev` | CISA KEV catalog |
| `reports/sitewriter` | Markdown website generation |

## Installation

```bash
go install github.com/grokify/govex/cmd/govex@latest
```

## License

MIT License - see [LICENSE](https://github.com/grokify/govex/blob/main/LICENSE) for details.
