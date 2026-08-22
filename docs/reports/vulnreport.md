# Vulnerability Report (vulnreport)

The `reports/vulnreport` package renders a `VulnerabilitiesSet` as a titled report in **Markdown**, **HTML**, and **PDF**, plus JSON for round-tripping. The `VulnerabilitiesSet` remains the data IR; `vulnreport.Report` adds report-level metadata and presentation.

## Installation

```go
import "github.com/grokify/govex/reports/vulnreport"
```

## Report

```go
r := vulnreport.NewReport("Q3 Vulnerability Report", set)
r.Subtitle = "Example App Security Assessment"
r.Organization = "Example Corp"
r.Author = "Security Team"
r.Classification = "Confidential" // rendered as a banner in HTML/PDF
r.GeneratedAt = &generatedTime
r.PeriodStart = &periodStart
r.PeriodEnd = &periodEnd
r.Summary = "Executive summary text. Blank lines separate paragraphs."
```

All metadata fields are optional; empty fields are omitted from the rendered header block. The header also includes the set's name, repository URL, data-as-of date, and finding count.

## Rendering

```go
md, err := r.Markdown()
html, err := r.HTML()
pdf, err := r.PDF() // []byte

err = r.WriteMarkdownFile("report.md", 0600)
err = r.WriteHTMLFile("report.html", 0600)
err = r.WritePDFFile("report.pdf", 0600)
err = r.WriteJSONFile("report.json", 0600)
```

Every format renders the same structure: classification banner, title, subtitle, metadata block, executive summary, severity summary table (counts ordered Critical to Low with a Total row), and the findings table.

After the findings table, HTML and Markdown output add a **Finding Details** section: one block per finding (an `h3`/`###` heading) with its name, ID, severity, inherent risk, description, and — when compensating controls exist — residual severity, residual risk, and each control's name and description in bold/italic emphasis (marked *(verified)* where applicable). Empty fields are omitted.

HTML output is a standalone page with inline styles; all cell values and metadata are HTML-escaped. Markdown output uses GitHub-flavored heading levels, tables, and bold/italic emphasis. PDF output uses [maroto](https://github.com/johnfercher/maroto) with page numbers and margins.

## Findings Columns

The findings table uses `DefaultColumnDefinitionSet()` unless `Report.ColumnSet` is set:

```go
// Default: Severity, ID, Name, Category, Library, Library Version, Fixed Version
cols := vulnreport.DefaultColumnDefinitionSet()

// Residual-aware: ID, Name, Severity, Residual Severity, Residual Risk,
// Exception Status, Compensating Controls
cols = vulnreport.ResidualColumnDefinitionSet()
r.ColumnSet = &cols
```

`ResidualColumnDefinitionSet` renders the inherent vs. residual assessment model — see [Compensating Controls & Residual Risk](../reference/residual-risk.md). The residual field names are also available for custom column sets:

```go
cols := table.ColumnDefinitionSet{
    Definitions: []table.ColumnDefinition{
        {Name: govex.FieldID, SourceName: govex.FieldID},
        {Name: govex.FieldSeverity, SourceName: govex.FieldSeverity},
        {Name: govex.FieldSeverityResidual, SourceName: govex.FieldSeverityResidual},
        {Name: govex.FieldSeverityEffective, SourceName: govex.FieldSeverityEffective},
        {Name: govex.FieldRiskInherent, SourceName: govex.FieldRiskInherent},
        {Name: govex.FieldRiskResidual, SourceName: govex.FieldRiskResidual},
        {Name: govex.FieldExceptionStatus, SourceName: govex.FieldExceptionStatus},
        {Name: govex.FieldControls, SourceName: govex.FieldControls},
    },
}
```

`FieldSeverityEffective` evaluates the exception state at `Vulnerability.ProcSLAEvalTime`; set it before rendering time-sensitive reports.

!!! note "PDF column limit"
    The PDF renderer distributes maroto's 12-cell grid across the table's columns, so a findings table may have at most 12 columns. Wider column sets return an error suggesting a narrower `ColumnSet`; Markdown and HTML have no such limit.

## CLI

The `govex report` subcommand exposes this package — see [govex report](../cli/report.md):

```bash
govex report -i vulns.json -o report.html --columns residual
```

## Example

Generate example output in all formats:

```bash
go run github.com/grokify/govex/reports/vulnreport/cmd/example
```

## Related

- [Compensating Controls & Residual Risk](../reference/residual-risk.md) - The inherent/residual model
- [Core Package](../packages/core.md) - VulnerabilitiesSet and column definitions
- [Reports Overview](index.md) - Other report types
