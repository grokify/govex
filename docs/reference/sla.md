# SLA Management

GoVEX tracks remediation Service Level Agreements (SLAs) with severity-based policies: each severity level gets a number of days to remediate, and every vulnerability's age is evaluated against the policy for its **effective severity**.

## SLA Policies

### SLAPolicy

`severity.SLAPolicy` defines remediation days for the four actionable severity levels:

```go
import "github.com/grokify/govex/severity"

policy := severity.SLAPolicy{
    CriticalDays: 15,
    HighDays:     30,
    MediumDays:   90,
    LowDays:      180,
}
```

Informational and None findings are not vulnerabilities requiring remediation and have no SLA days; severities without configured days return 0 and produce no due date via `SLAOptions.DueDate`.

### SLAMap and Predefined Policies

`severity.SLAMap` is a simple severity → days map, with predefined policies for common frameworks:

```go
fedramp := severity.SLAMapFedRAMP() // Critical/High: 30, Medium: 90, Low: 180
gitlab := severity.SLAMapGitLab()   // Critical/High: 30, Medium: 90, Low: 180
```

## Policy Methods

```go
// Due date for a severity from a start time
due, err := policy.DueDate("High", detectedTime)

// Overdue check from an age
overdueBy, isOverdue, err := policy.IsOverdue("High", age)

// Days configured for a severity
days := policy.SeveritySLADays("High") // 30

// Render the policy for reports
md := policy.Markdown()
tbl := policy.Table()
```

## SLA Statuses

Status strings for reporting:

| Constant | Value | Meaning |
|----------|-------|---------|
| `StatusWithinSLA` | Within SLA | Age is inside the remediation window |
| `StatusApproachingSLA` | Approaching SLA | Nearing the SLA threshold |
| `StatusOutOfSLA` | Out of SLA | The remediation window has been breached |

```go
status, err := policy.SLAStatusTimesString("High", &startTime, evalTime, "Unknown")
// "Within SLA" or "Out of SLA"; the unknown string when startTime is nil
```

## Vulnerability SLA Methods

`govex.Vulnerability` evaluates its own SLA state against a policy. The SLA clock starts at `SLATimeStart`:

```go
vn := govex.Vulnerability{
    Severity:     "High",
    SLATimeStart: &detectedTime,
}

overdueBy := vn.SLAOverdueDuration(policy, time.Now()) // 0 if within SLA
compliant := vn.SLACompliant(policy, time.Now())
elapsed := vn.SLAElapsed(policy, time.Now())
ageDays, overdueDays, overdue := vn.SLAInfo(slaMap, time.Now())

// Sets and returns vn.SLAStatus for report columns
status := vn.BuildSLAStatusString(policy, time.Now(), "Unknown")
```

## Effective Severity: Exceptions Switch the SLA Basis

All vulnerability SLA methods key off `EffectiveSeverity`, not the raw `Severity` field. The policy is:

> The SLA clock runs on **inherent severity** until a risk exception is approved, then on **residual severity** for as long as the approval is in effect.

```go
vn := govex.Vulnerability{
    Severity:         "High", // inherent: 30-day SLA
    SeverityResidual: "Low",  // residual: 180-day SLA
    SLATimeStart:     &detectedTime,
}

// Before approval: evaluated as High.
vn.SLACompliant(policy, evalTime)

// After approval: evaluated as Low.
vn.Exception = &govex.ExceptionStatus{
    Status:     govex.ExceptionStatusApproved,
    ApprovedAt: &approvedTime,
    ExpiresAt:  &expiryTime,
}
vn.SLACompliant(policy, evalTime)

// After expiry: evaluated as High again.
```

A residual severity with a merely requested or rejected exception has no effect on the SLA. See [Compensating Controls & Residual Risk](residual-risk.md) for the full model.

## SLA Start Dates

`severity.SLAOptions` resolves the SLA start time with explicit precedence — a hard per-finding start date, then a fixed program-wide start date, then the finding's soft start date:

```go
opts := severity.SLAOptions{
    SLAStartDateFixed: &programStartDate,
    SLAPolicy:         &policy,
}

due, err := opts.DueDate("High", softStart, hardStart)
// hardStart > SLAStartDateFixed > softStart; nil when no SLA days configured
```

## Related

- [Severity Package](../packages/severity.md) - Severity classification underlying SLA policies
- [Compensating Controls & Residual Risk](residual-risk.md) - Exception workflow and effective severity
- [Vulnerability Status](status.md) - Remediation status vocabulary
