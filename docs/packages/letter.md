# Letter Package

The `letter` package generates security notification letters for vulnerability findings.

## Installation

```go
import "github.com/grokify/govex/letter"
```

## Letter Types

| Type | Constant | Description |
|------|----------|-------------|
| SLA Exception | `letter.TypeSLA` | Notification when remediation exceeds SLA |
| Hardening Notice | `letter.TypeHardening` | Defense-in-depth improvement notice |

## Types

### Letter

The main letter structure:

```go
type Letter struct {
    SchemaVersion string
    Type          string  // "sla" or "hardening"
    Subject       string
    Sender        Sender
    CustomerName  string
    Application   string
    Finding       Finding
    CVSS          *CVSS

    // SLA-specific
    SLA          *SLA
    DelayReasons []string

    // Hardening-specific
    Rationale  string
    TargetDate string

    // Shared
    RiskAssessment   string
    Mitigations      []string
    RemediationPlan  string
    Milestones       []Milestone
    Approver         *Approver
    EscalationPolicy []string
}
```

### Sender

```go
type Sender struct {
    Name    string
    Title   string
    Team    string
    Company string
    Email   string
    Phone   string // optional
}
```

### Finding

```go
type Finding struct {
    Title      string
    Severity   string // Low, Moderate, High, Critical
    Identifier string
    DetectedOn string // YYYY-MM-DD
}
```

### SLA

```go
type SLA struct {
    TargetDays      int
    OriginalDueDate string // YYYY-MM-DD
    NewDueDate      string // YYYY-MM-DD
}
```

### Milestone

```go
type Milestone struct {
    Phase          int
    Description    string
    TargetDate     string
    CustomerImpact string
}
```

## Creating Letters

### SLA Exception Letter

```go
ltr := letter.NewLetter(letter.TypeSLA)
ltr.CustomerName = "Widget Inc"
ltr.Application = "Payments API"
ltr.Sender = letter.Sender{
    Name:    "Jane Smith",
    Title:   "Security Engineer",
    Team:    "Application Security",
    Company: "Acme Corp",
    Email:   "security@acme.com",
}
ltr.Finding = letter.Finding{
    Title:      "Missing rate limiting",
    Severity:   "Low",
    Identifier: "APPSEC-1234",
    DetectedOn: "2026-04-01",
}
ltr.SLA = &letter.SLA{
    TargetDays:      90,
    OriginalDueDate: "2026-06-30",
    NewDueDate:      "2026-07-31",
}
ltr.DelayReasons = []string{"Dependent on upstream API change"}
ltr.RiskAssessment = "Low likelihood due to internal access"
ltr.Mitigations = []string{"WAF rate limiting in place"}
ltr.RemediationPlan = "Implement native rate limiting"
ltr.SetSubjectFromFinding()
```

### Hardening Notice

```go
ltr := letter.NewLetter(letter.TypeHardening)
ltr.CustomerName = "Widget Inc"
ltr.Application = "Customer Portal"
ltr.Finding = letter.Finding{
    Title:      "CSP Configuration Enhancement",
    Severity:   "Low",
    Identifier: "APPSEC-5678",
    DetectedOn: "2026-04-01",
}
ltr.Rationale = "Defense-in-depth improvement to strengthen CSP"
ltr.TargetDate = "2026-08-01"
ltr.SetSubjectFromFinding()
```

## Output Formats

### JSON

```go
// Write to file
err := ltr.WriteFile("letter.json")

// Get JSON string
jsonStr, err := ltr.JSON()
```

### Markdown

Generate Pandoc-compatible Markdown for DOCX/PDF conversion:

```go
// Write to file
err := ltr.WriteMarkdownFile("letter.md")

// Get Markdown string
md := ltr.Markdown()
```

### Converting to DOCX/PDF

Use Pandoc to convert the Markdown output:

```bash
# To DOCX
pandoc letter.md -o letter.docx

# To PDF
pandoc letter.md -o letter.pdf
```

## File Operations

### Reading from JSON

```go
ltr, err := letter.ReadFile("finding.json")
```

## JSON Schema

Get the JSON Schema for validation or AI integration:

```go
schema, err := letter.JSONSchema()
schemaStr, err := letter.JSONSchemaString()
```

## CLI Integration

The letter package powers the `govex letter` CLI command:

```bash
govex letter generate --input finding.json --output-md letter.md
govex letter schema
govex letter example --type sla
```

See [CLI Reference](../cli/letter.md) for complete command documentation.
