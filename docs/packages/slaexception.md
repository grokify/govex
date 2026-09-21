# SLA Exception Package

The `slaexception` package generates SLA exception notification letters for security findings. An `Exception` is a JSON intermediate representation (IR) that renders to Pandoc-style Markdown for conversion to DOCX or PDF, and it emits a JSON Schema for AI-agent integration.

## Installation

```go
import "github.com/grokify/govex/slaexception"
```

## Exception

`Exception` is the top-level document. Its JSON tags are snake_case and it carries a `schema_version` field pinned to the current `SchemaVersion` constant (`"1.0"`):

| Field | JSON | Type | Notes |
|-------|------|------|-------|
| `SchemaVersion` | `schema_version` | `string` | Schema version for the document format |
| `Subject` | `subject` | `string` | Email subject line for the notification |
| `Sender` | `sender` | `Sender` | Sender/signatory information |
| `CustomerName` | `customer_name` | `string` | Customer receiving the notification |
| `Application` | `application` | `string` | Affected application |
| `Finding` | `finding` | `Finding` | Security finding details |
| `CVSS` | `cvss` | `*CVSS` | CVSS scoring details (optional) |
| `SLA` | `sla` | `SLA` | SLA timeline information |
| `DelayReasons` | `delay_reasons` | `[]string` | Reasons for the remediation delay |
| `RiskAssessment` | `risk_assessment` | `string` | Assessment of the risk posed |
| `Mitigations` | `mitigations` | `[]string` | Mitigating controls in place |
| `RemediationPlan` | `remediation_plan` | `string` | Plan for remediating the finding |
| `Milestones` | `milestones` | `[]Milestone` | Phased remediation milestones (optional) |
| `Approver` | `approver` | `*Approver` | Senior leader who approved the exception (optional) |
| `EscalationPolicy` | `escalation_policy` | `[]string` | Actions if the threat landscape changes (optional) |

## Nested Types

### Sender

| Field | JSON | Type | Notes |
|-------|------|------|-------|
| `Name` | `name` | `string` | Full name of the sender |
| `Title` | `title` | `string` | Job title of the sender |
| `Team` | `team` | `string` | Team or department |
| `Company` | `company` | `string` | Company name |
| `Email` | `email` | `string` | Email address |
| `Phone` | `phone` | `string` | Phone number (optional) |

### Finding

| Field | JSON | Type | Notes |
|-------|------|------|-------|
| `Title` | `title` | `string` | Title of the security finding |
| `Severity` | `severity` | `string` | One of `Low`, `Moderate`, `High`, `Critical` |
| `Identifier` | `identifier` | `string` | Unique identifier for the finding |
| `DetectedOn` | `detected_on` | `string` | Detection date (ISO 8601 `YYYY-MM-DD`) |

### CVSS

| Field | JSON | Type | Notes |
|-------|------|------|-------|
| `Score` | `score` | `float64` | CVSS numeric score (0.0-10.0) |
| `Version` | `version` | `string` | CVSS version used for scoring |
| `Vector` | `vector` | `string` | CVSS vector string |

### SLA

| Field | JSON | Type | Notes |
|-------|------|------|-------|
| `TargetDays` | `target_days` | `int` | Target days for remediation based on severity |
| `OriginalDueDate` | `original_due_date` | `string` | Original SLA due date (ISO 8601 `YYYY-MM-DD`) |
| `NewDueDate` | `new_due_date` | `string` | New expected remediation date (ISO 8601 `YYYY-MM-DD`) |

### Milestone

| Field | JSON | Type | Notes |
|-------|------|------|-------|
| `Phase` | `phase` | `int` | Phase number |
| `Description` | `description` | `string` | What this phase delivers |
| `TargetDate` | `target_date` | `string` | Target completion date (ISO 8601 `YYYY-MM-DD`) |
| `CustomerImpact` | `customer_impact` | `string` | Expected impact to customers |

### Approver

| Field | JSON | Type | Notes |
|-------|------|------|-------|
| `Name` | `name` | `string` | Full name of the approver |
| `Title` | `title` | `string` | Job title of the approver |
| `ApprovalDate` | `approval_date` | `string` | Date of approval (ISO 8601 `YYYY-MM-DD`) |

## Rendering Markdown

`Exception.Markdown()` returns Pandoc-style Markdown, formatting ISO dates as human-readable (e.g., `June 30, 2026`). `Exception.WriteMarkdownFile(filename)` writes that output to a file:

```go
exc := &slaexception.Exception{
    SchemaVersion: slaexception.SchemaVersion,
    Subject:       "SLA Exception – Low – Missing rate limiting",
    Sender: slaexception.Sender{
        Name:    "Jane Smith",
        Title:   "Security Engineer",
        Team:    "Application Security",
        Company: "Acme Corp",
        Email:   "security@acme.com",
    },
    CustomerName: "Widget Inc",
    Application:  "Payments API",
    Finding: slaexception.Finding{
        Title:      "Missing rate limiting",
        Severity:   "Low",
        Identifier: "APPSEC-1234",
        DetectedOn: "2026-04-01",
    },
    SLA: slaexception.SLA{
        TargetDays:      90,
        OriginalDueDate: "2026-06-30",
        NewDueDate:      "2026-07-31",
    },
    DelayReasons:    []string{"Dependent on upstream API gateway change"},
    RiskAssessment:  "Low likelihood of exploitation due to internal-only access.",
    Mitigations:     []string{"WAF rate limiting rules in place"},
    RemediationPlan: "Implement native rate limiting in service layer",
}

md := exc.Markdown()                     // Pandoc Markdown as a string
err := exc.WriteMarkdownFile("letter.md") // or write it to a file
```

## JSON Schema

`JSONSchema()` (and `JSONSchemaString()`) reflect a JSON Schema describing the `Exception` format, titled "SLA Exception Notification". The schema lets AI agents, validators, and documentation tools understand the expected input structure:

```go
schema, err := slaexception.JSONSchemaString()
```

## Related

- [govex slaletter](../cli/slaletter.md) - CLI for generating SLA exception letters
- [Letter Package](letter.md) - Notification-letter package for SLA and hardening notices
