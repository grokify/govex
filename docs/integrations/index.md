# Integrations Overview

GoVEX integrates with popular security scanning tools and vulnerability feeds.

## Analyzers

Convert output from security analysis tools to GoVEX format.

| Tool | Package | Description |
|------|---------|-------------|
| [Semgrep](semgrep.md) | `analyzers/semgrep` | SAST with CWE/OWASP mapping |
| [SpotBugs](spotbugs.md) | `analyzers/spotbugs` | Java security analysis |

## Feeds

Ingest vulnerability data from external sources.

| Source | Package | Description |
|--------|---------|-------------|
| [CISA KEV](cisakev.md) | `feeds/cisakev` | Known Exploited Vulnerabilities |

## External Integrations

Additional integrations available as separate packages:

| Tool | Package | Description |
|------|---------|-------------|
| Grype | [github.com/grokify/gogrype](https://github.com/grokify/gogrype) | Container vulnerability scanner |

## Integration Pattern

All analyzers follow a similar pattern:

```go
// 1. Parse tool-specific output
results, err := semgrep.ParseFile("semgrep-results.json")

// 2. Convert to GoVEX format
vulns := results.ToVulnerabilities()

// 3. Use standard GoVEX operations
table := vulns.Table(govex.TableColumnDefinitionSetSASTSCAReport())
```

## Merging Multiple Sources

Combine results from multiple tools:

```go
import "github.com/grokify/govex/analyzers"

// Merge vulnerability sets from different sources
merged := analyzers.MergeVulnerabilities(
    semgrepVulns,
    spotbugsVulns,
    grypeVulns,
)
```

Or use the CLI:

```bash
govex merge \
  --input semgrep.json \
  --input spotbugs.json \
  --output combined.json
```
