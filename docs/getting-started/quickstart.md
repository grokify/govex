# Quick Start

This guide walks through common GoVEX workflows.

## Using the Library

### Creating Vulnerabilities

```go
package main

import (
    "github.com/grokify/govex"
)

func main() {
    // Create vulnerability records
    vulns := govex.Vulnerabilities{
        {
            ID:          "CVE-2024-1234",
            Title:       "SQL Injection vulnerability",
            Severity:    "High",
            Status:      "Open",
            Module:      "backend-api",
            Description: "User input not sanitized in login endpoint",
        },
        {
            ID:          "CVE-2024-5678",
            Title:       "XSS in comment field",
            Severity:    "Medium",
            Status:      "In Progress",
            Module:      "frontend",
        },
    }

    // Generate a report table
    table := vulns.Table(govex.TableColumnDefinitionSetSASTSCAReport())

    // Export to different formats
    table.WriteXLSX("report.xlsx")
    table.WriteCSV("report.csv")
}
```

### Filtering Vulnerabilities

```go
// Filter by severity
highSeverity := vulns.FilterSeverity("High")

// Filter by module
apiVulns := vulns.FilterModule("backend-api")

// Filter by status
openVulns := vulns.FilterStatus("Open")
```

### SLA Tracking

```go
import "github.com/grokify/govex/severity"

// Define SLA policy (days to remediate by severity)
policy := severity.SLAMap{
    "Critical": 7,
    "High":     30,
    "Medium":   90,
    "Low":      180,
}

// Check if a vulnerability is overdue
isOverdue := policy.IsOverdue("High", detectedDate)
```

## Using the CLI

### Merging Vulnerability Files

Combine multiple JSON vulnerability files:

```bash
govex merge --input vulns1.json --input vulns2.json --output combined.json
```

### Generating Security Letters

Generate an SLA exception notification:

```bash
# View example JSON format
govex letter example --type sla

# Generate from JSON input
govex letter generate --input finding.json --output-md letter.md

# Generate with command-line parameters
govex letter generate \
  --type sla \
  --customer "Acme Corp" \
  --application "Payment API" \
  --finding-title "Missing rate limiting" \
  --finding-severity Low \
  --finding-id APPSEC-1234 \
  --finding-date 2026-04-01 \
  --sla-target-days 90 \
  --sla-original-date 2026-06-30 \
  --sla-new-date 2026-07-31 \
  --delay-reason "Dependent on upstream change" \
  --risk "Low likelihood due to internal access" \
  --mitigation "WAF rules in place" \
  --remediation "Implement native rate limiting" \
  --sender-name "Jane Smith" \
  --sender-title "Security Engineer" \
  --sender-team "Application Security" \
  --sender-company "Acme Corp" \
  --sender-email "security@acme.com" \
  --output-md letter.md
```

### Generating Hardening Notices

```bash
govex letter example --type hardening
govex letter generate --type hardening --input notice.json --output-md letter.md
```

## Next Steps

- [CLI Reference](../cli/index.md) - Complete command documentation
- [Packages](../packages/core.md) - Library API reference
- [Integrations](../integrations/index.md) - Connect with security tools
