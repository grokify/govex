# Severity Package

The `severity` package provides severity classification, SLA policies, and statistics.

## Installation

```go
import "github.com/grokify/govex/severity"
```

## Severity Levels

Standard severity levels:

| Level | Description |
|-------|-------------|
| Critical | Immediate action required |
| High | Urgent remediation needed |
| Medium | Moderate priority |
| Low | Lower priority |
| Informational | For awareness only |

## SLA Policies

### SLAMap

Define remediation timelines by severity:

```go
policy := severity.SLAMap{
    "Critical": 7,   // 7 days
    "High":     30,  // 30 days
    "Medium":   90,  // 90 days
    "Low":      180, // 180 days
}
```

### Checking SLA Status

```go
// Check if overdue
isOverdue := policy.IsOverdue("High", detectedDate)

// Get target days for severity
days := policy.TargetDays("High") // returns 30
```

### Predefined Policies

```go
// Common SLA policy
policy := severity.SLAMapDefault()
```

## Severity Statistics

### SeverityStats

Track vulnerability counts by severity:

```go
stats := severity.NewSeverityStats()
stats.Add("High")
stats.Add("High")
stats.Add("Low")

// Get counts
highCount := stats.Count("High") // 2
total := stats.Total()           // 3
```

### SeverityStatsSet

Named statistics for multiple categories:

```go
statsSet := severity.SeverityStatsSet{
    "backend":  stats1,
    "frontend": stats2,
}
```

## Severity Status

Track remediation status with severity context:

```go
type SeverityStatus struct {
    Severity string
    Status   string
    Count    int
}
```

### SeverityStatusSet

```go
statusSet := severity.SeverityStatusSet{}
statusSet.Add("High", "Open")
statusSet.Add("High", "In Progress")
```

## Severity Counts

### SeverityCounts

Simple count tracking:

```go
counts := severity.SeverityCounts{
    Critical: 2,
    High:     5,
    Medium:   10,
    Low:      20,
}

total := counts.Total() // 37
```

## Scores

### Severity to Score Mapping

Convert severity levels to numeric scores:

```go
score := severity.SeverityToScore("High") // returns numeric score

// Get score table
table := severity.SeverityToScoreTable()
md := severity.SeverityToScoreTableMarkdown()
```

## Related

- [Core Package](core.md) - Vulnerability types with severity fields
- [SLA Management](../reference/sla.md) - SLA workflow reference
