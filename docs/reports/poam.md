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
