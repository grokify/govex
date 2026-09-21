# ExceptionRequest Package

The `exceptionrequest` package models vulnerability risk-exception requests tracked through an approval workflow. Each request records why a specific finding is being accepted rather than remediated, the compensating controls in place, and the risk characteristics reviewers weigh when approving or denying the exception.

## Installation

```go
import "github.com/grokify/govex/exceptionrequest"
```

## Request

A `Request` is a single risk-exception request tied to one `Vulnerability`. Its fields capture the request's provenance, timeline, risk characteristics, and approval state:

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `string` | Exception identifier |
| `InRelease` | `bool` | Whether the affected implementation is in a release |
| `Vulnerability` | `Vulnerability` | The finding the exception covers |
| `ApplicationDate` | `*time.Time` | When the exception was requested |
| `ExceptionEndDate` | `*time.Time` | When the exception expires |
| `Department` | `string` | Owning department |
| `RequestorEmail` | `string` | Requestor's email address |
| `Description` | `string` | Free-text description |
| `ExposesPII` | `*bool` | Whether exploitation exposes PII |
| `RequiresCompromisingTenant` | `*bool` | Whether exploitation requires compromising a tenant |
| `EnablesLateralMovement` | `*bool` | Whether exploitation enables lateral movement |
| `CompensatingControlsDescription` | `string` | Controls mitigating the residual risk |
| `Risk` | `string` | Risk characterization |
| `CVSSScore` | `float32` | CVSS base score |
| `CVSSVersion` | `float32` | CVSS version |
| `ExceptionURL` | `string` | Link to the exception record |
| `ReferenceURL` | `string` | Link to the implementation/reference record |
| `IsClosed` | `bool` | Whether the request has been closed |

The three risk-characteristic fields are `*bool` so that "unknown" (nil) is distinct from an explicit true/false. The following accessors render them, along with the exception end date, as strings suitable for tables and reports:

```go
req := exceptionrequest.Request{
    ID:                              "SER-1001",
    Department:                      "Platform",
    RequestorEmail:                  "owner@example.com",
    Description:                     "Third-party dependency finding pending upstream fix.",
    CompensatingControlsDescription: "Network segmentation and WAF rule in place.",
    CVSSScore:                       7.5,
    CVSSVersion:                     3.1,
    ExceptionURL:                    "https://tracker.example.com/ser/1001",
}

_ = req.ExceptionEndDateString()          // "" when ExceptionEndDate is nil, else YYYY-MM-DD
_ = req.ExposesPIIString()                // "" for nil, otherwise "true"/"false"
_ = req.EnablesLateralMovementString()    // ""/"true"/"false"
_ = req.RequiresCompromisingTenantString()// ""/"true"/"false"
_ = req.ExceptionLink()                   // markdown link, or "<ID> - no SER" when ExceptionURL is empty
```

## Vulnerability

A `Request` embeds a `Vulnerability`, the finding under exception. It carries the identifiers and per-team severity/reporting state used when rendering exception tables:

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `string` | Vulnerability identifier |
| `AliasIDs` | `[]string` | Alternate identifiers |
| `ItemType` | `string` | Finding type |
| `SeverityEngineering` | `string` | Engineering-assessed severity |
| `SeverityAppSecEnvironmental` | `string` | AppSec environmental severity |
| `SeverityAppSecResidual` | `string` | AppSec residual severity |
| `ReportedAppSec` | `bool` | Reported by AppSec |
| `ReportedEngineering` | `bool` | Reported by Engineering |
| `ReportedExceptionRequest` | `bool` | Reported via exception request |
| `Parent` | `*Vulnerability` | Optional parent finding |

`Vulnerabilities` is a `[]Vulnerability` slice type. `VulnerabilitiesSet` is an ID-keyed collection; construct it with `NewVulnerabilitiesSet()` and populate it with `Add`:

```go
set := exceptionrequest.NewVulnerabilitiesSet()
set.Add(
    exceptionrequest.Vulnerability{ID: "VULN-1", SeverityAppSecResidual: "Medium"},
    exceptionrequest.Vulnerability{ID: "VULN-2", SeverityAppSecResidual: "Low"},
)
// set.Data is map[string]Vulnerability keyed by ID
```

## Requests

`Requests` is a `[]Request` slice type with lookup and rendering helpers:

| Method | Returns | Notes |
|--------|---------|-------|
| `IDsMap()` | `map[string]int` | Counts occurrences of each request ID |
| `Request(id)` | `(*Request, error)` | Returns the request with the given ID, or an error if not found |
| `Table()` | `*table.Table` | Renders the requests as a `gocharts` table |

```go
reqs := exceptionrequest.Requests{
    {
        ID:          "SER-1001",
        Description: "Awaiting upstream patch.",
        Vulnerability: exceptionrequest.Vulnerability{
            ID:                          "VULN-1",
            SeverityAppSecEnvironmental: "High",
            SeverityAppSecResidual:      "Medium",
        },
        ExceptionURL: "https://tracker.example.com/ser/1001",
    },
}

tbl := reqs.Table()
_ = tbl // render with the gocharts table writers

found, err := reqs.Request("SER-1001")
if err != nil {
    // handle not-found
}
_ = found
```

## SERSet

`SERSet` is an ID-keyed set of requests. Construct it with `NewSERSet()`, add requests with `Add`, and render with `Table()`, which produces a wider table than `Requests.Table()` — including aliases, in-release state, and all three per-team severities:

```go
set := exceptionrequest.NewSERSet()
set.Add(reqs...)
tbl := set.Table()
_ = tbl
```

## RequestSet and Status

`RequestSet` categorizes filed exception IDs against their approval state. It holds the full list of filed `IDs` plus the `Approved` and `InProgress` request slices:

```go
set := exceptionrequest.NewRequestSet()
set.IDs = []string{"SER-1001", "SER-1002", "SER-1003"}
set.Approved = exceptionrequest.Requests{{ID: "SER-1001"}}
set.InProgress = exceptionrequest.Requests{
    {ID: "SER-1002"},
    {ID: "SER-1003", IsClosed: true},
}

stats := set.Status()
```

`Status()` returns a `StatusStats` that buckets every filed ID (sorted). A request found in `InProgress` with `IsClosed` set is counted as closed; otherwise it is recorded against approved and/or in-progress; IDs matching neither are flagged as not categorized:

| Field | Meaning |
|-------|---------|
| `IDsFiledAll` | Every filed ID |
| `IDsFiledClosed` | Filed and closed |
| `IDsFiledApproved` | Filed and approved |
| `IDsFiledInProgress` | Filed and in progress |
| `IDsFiledNotCategorized` | Filed but matching neither approved nor in-progress |

## Related

- [Severity Package](severity.md) - Severity classification carried on each `Vulnerability`
- [Compensating Controls & Residual Risk](../reference/residual-risk.md) - Conceptual model behind compensating controls and residual risk
