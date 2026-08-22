# Core Package (govex)

The core `govex` package provides the fundamental types and functions for vulnerability management.

## Installation

```go
import "github.com/grokify/govex"
```

## Types

### Vulnerability

Represents a single vulnerability finding.

```go
type Vulnerability struct {
    ID          string
    Title       string
    Description string
    Severity    string
    Status      string
    Module      string
    Category    string
    CWE         string
    CVSS        float64
    CVSSVector  string
    DetectedOn  time.Time
    // ... additional fields
}
```

#### Residual Assessment Fields

A vulnerability also carries its assessment before and after compensating controls:

```go
type Vulnerability struct {
    // ...
    Severity               string                // inherent severity (CVSS base)
    SeverityResidual       string                // residual severity (CVSS environmental)
    SeverityResidualVector string                // environmental vector justifying the residual
    RiskInherent           *risk.Rating          // likelihood × impact without controls
    RiskResidual           *risk.Rating          // likelihood × impact with verified controls
    Controls               []CompensatingControl // controls justifying the residual assessments
    Exception              *ExceptionStatus      // exception approval state
    // ...
}
```

See [Compensating Controls & Residual Risk](../reference/residual-risk.md) for the full model.

### CompensatingControl

A measure that reduces exploitability or impact without remediating the vulnerability:

```go
control := govex.CompensatingControl{
    ID:              "CTRL-NET-001",
    Name:            "Network segmentation",
    Function:        govex.ControlFunctionPreventive, // or Detective, Corrective
    Reduces:         []string{govex.ReducesLikelihood},
    ModifiedMetrics: []string{"MAV:A"},
    Effectiveness:   govex.EffectivenessHigh,
    Verified:        true,
}
```

### ExceptionStatus

Approval state of a risk exception. The SLA clock runs on inherent severity until an exception is approved, then on residual severity:

```go
vn.Exception = &govex.ExceptionStatus{
    Status:     govex.ExceptionStatusApproved,
    ApprovedAt: &approvedTime,
    ExpiresAt:  &expiryTime,
}

sev := vn.EffectiveSeverity(time.Now()) // residual while approval in effect

err := vn.ValidateResidualSeverity() // residual must be Critical–Low and ≤ inherent
```

### Vulnerabilities

A slice of Vulnerability with convenience methods.

```go
type Vulnerabilities []Vulnerability
```

### VulnerabilitiesSet

A named collection of vulnerabilities with metadata.

```go
type VulnerabilitiesSet struct {
    Name            string
    Vulnerabilities Vulnerabilities
    Meta            VulnerabilitiesSetMeta
}
```

## Core Functions

### Creating Vulnerabilities

```go
vulns := govex.Vulnerabilities{
    {
        ID:       "CVE-2024-1234",
        Title:    "SQL Injection",
        Severity: "High",
        Status:   "Open",
    },
}
```

### Filtering

```go
// Filter by severity
high := vulns.FilterSeverity("High")

// Filter by module
api := vulns.FilterModule("backend-api")

// Filter by status
open := vulns.FilterStatus("Open")

// Filter by category
sast := vulns.FilterCategory(govex.CategorySAST)
```

### Table Generation

Generate tables for reporting:

```go
// Use predefined column set
table := vulns.Table(govex.TableColumnDefinitionSetSASTSCAReport())

// Export to formats
table.WriteXLSX("report.xlsx")
table.WriteCSV("report.csv")
md := table.Markdown()
```

### Statistics

```go
stats := vulns.SeverityStats()
// Returns counts by severity level
```

## Categories

Predefined vulnerability categories:

| Constant | Description |
|----------|-------------|
| `CategorySAST` | Static Application Security Testing |
| `CategorySCA` | Software Composition Analysis |
| `CategoryDAST` | Dynamic Application Security Testing |
| `CategoryIaC` | Infrastructure as Code |
| `CategoryContainer` | Container security |

## Table Column Definitions

Predefined column sets for common report types:

```go
// SAST/SCA report columns
cols := govex.TableColumnDefinitionSetSASTSCAReport()

// Custom columns
cols := []govex.TableColumnDefinition{
    {Field: govex.FieldID, Header: "CVE"},
    {Field: govex.FieldSeverity, Header: "Severity"},
    {Field: govex.FieldTitle, Header: "Title"},
}
```

## File Operations

### Reading/Writing JSON

```go
// Read vulnerabilities from JSON file
vulns, err := govex.ReadVulnerabilitiesFile("vulns.json")

// Write vulnerabilities to JSON file
err := vulns.WriteFile("output.json")
```

## Related Packages

- [severity](severity.md) - Severity classification and SLA policies
- [risk](risk.md) - Risk ratings, matrices, and NIST SP 800-30 translation
- [letter](letter.md) - Security notification letters
