# Reports Overview

GoVEX provides various report generation capabilities.

## Report Types

| Package | Description |
|---------|-------------|
| [Site Writer](sitewriter.md) | Markdown website generation |
| [PSIRT Report](psirtreport.md) | PSIRT vulnerability reports |
| [Release BOM](releasebom.md) | Release manifest with vulnerabilities |
| [POAM](poam.md) | FedRAMP Plan of Action & Milestones |
| [Pentest Remediation](pentest.md) | Pentest remediation status reports |

## Basic Table Reports

All vulnerability sets can generate tabular reports:

```go
// Generate table with standard columns
table := vulns.Table(govex.TableColumnDefinitionSetSASTSCAReport())

// Export formats
table.WriteXLSX("report.xlsx")
table.WriteCSV("report.csv")
md := table.Markdown()
```

## Custom Column Selection

```go
cols := []govex.TableColumnDefinition{
    {Field: govex.FieldID, Header: "CVE"},
    {Field: govex.FieldSeverity, Header: "Severity"},
    {Field: govex.FieldTitle, Header: "Title"},
    {Field: govex.FieldStatus, Header: "Status"},
    {Field: govex.FieldModule, Header: "Component"},
}

table := vulns.Table(cols)
```

## Markdown Reports

Generate Markdown for documentation sites:

```go
md := vulns.MarkdownTable()
```

## Overdue Reports

Track SLA compliance:

```go
// Get overdue vulnerabilities
overdue := vulns.TableOverdue(slaPolicy)
```
