# Standards Overview

GoVEX supports common vulnerability and security standards.

## Supported Standards

| Standard | Package | Description |
|----------|---------|-------------|
| [CVE 2.0](cve.md) | `standards/cve20` | NIST CVE format |
| [CVSS](cvss.md) | `standards/cvss30` | Vulnerability scoring |
| [CWE](cwe.md) | `standards/cwe` | Weakness enumeration |
| [CSAF](csaf.md) | `standards/csaf` | Security advisories |

## Standards Comparison

For a detailed comparison of vulnerability reporting formats, see [Vulnerability Formats](../reference/vulnerability-formats.md).

## Usage Pattern

All standards packages follow a similar pattern:

```go
// Parse standard format
data, err := cve20.ParseFile("cve.json")

// Convert to GoVEX format
vulns := data.ToVulnerabilities()

// Use standard GoVEX operations
table := vulns.Table(govex.TableColumnDefinitionSetSASTSCAReport())
```

## Integration with NVD

The `nvd` package provides an API client for the NIST National Vulnerability Database:

```go
import "github.com/grokify/govex/nvd"

client := nvd.NewClient(apiKey)
cve, err := client.GetCVE("CVE-2024-1234")
```
