# POAM (Plan of Action & Milestones)

Generate FedRAMP-compliant Plan of Action and Milestones documents.

## Installation

```go
import "github.com/grokify/govex/reports/poam"
```

## Overview

POA&M (Plan of Action and Milestones) is a document required for FedRAMP authorization that tracks:

- Known system weaknesses
- Planned remediation actions
- Target completion dates
- Responsible parties

## FedRAMP Context

POA&M is part of the FedRAMP (Federal Risk and Authorization Management Program) compliance framework. It documents how an organization plans to address security findings.

## Usage

### Create POAM Entry

```go
entry := poam.Entry{
    ID:              "POAM-001",
    Weakness:        "SQL Injection vulnerability in login form",
    PointOfContact:  "Security Team",
    Resources:       "2 developers, 1 sprint",
    ScheduledDate:   "2026-06-30",
    MilestoneChanges: "None",
    Status:          "In Progress",
}
```

### From Vulnerabilities

```go
entries := vulns.ToPOAMEntries()
```

### From findingspec findings

POA&M generation is scanner-agnostic: any adapter that emits the shared
[findingspec](https://github.com/plexusone/findingspec) IR — AWS Inspector,
Grype, Trivy, and others — can produce a POA&M table through
`poam.FromFindings`, without a scanner-specific adapter.

```go
import (
    "github.com/grokify/govex"
    "github.com/grokify/govex/reports/poam"
    "github.com/plexusone/findingspec"
)

// findings is []findingspec.Finding produced by any adapter.
tbl, err := poam.FromFindings(findings, &govex.ValueOptions{}, nil)
```

`poam.Finding` wraps a `findingspec.Finding` as a `POAMItem`, resolving
open/closed status, per-field values, CVE identifiers, and remediation-plan text
from the finding's security detail.

## POAM Fields

| Field | Description |
|-------|-------------|
| ID | Unique identifier |
| Weakness | Description of the finding |
| Point of Contact | Responsible party |
| Resources | Required resources |
| Scheduled Completion | Target date |
| Milestone Changes | Updates to timeline |
| Status | Current status |
| Comments | Additional notes |

## OSCAL Integration

POA&M is part of the OSCAL (Open Security Controls Assessment Language) standard. GoVEX POA&M output can be integrated with OSCAL workflows.

See [Vulnerability Formats](../reference/vulnerability-formats.md) for OSCAL vs CSAF comparison.

## Related

- [Vulnerability Formats](../reference/vulnerability-formats.md)
- [SLA Management](../reference/sla.md)
