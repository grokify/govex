# PSIRT Report

Generate Product Security Incident Response Team (PSIRT) reports.

## Installation

```go
import "github.com/grokify/govex/reports/psirtreport"
```

## Overview

PSIRT reports provide structured vulnerability summaries for security teams. Reports include:

- Vulnerability counts by severity
- Statistics by reporter (internal/external)
- Module-level breakdown
- Trend analysis

## Usage

### Generate Report

```go
report := psirtreport.Report(vulnSet)
```

### Report Sections

The report includes:

1. **Executive Summary** - High-level counts and trends
2. **By Severity** - Breakdown by severity level
3. **By Reporter** - Internal vs external findings
4. **By Module** - Per-component statistics
5. **Details** - Full vulnerability listing

## Reporter Filtering

Filter by reporter type:

```go
// External reporters (bug bounty, pen tests, etc.)
external := vulnSet.FilterReporterExternal()

// Internal reporters (SAST, SCA, internal review)
internal := vulnSet.FilterReporterInternal()
```

## Statistics

```go
stats := vulns.SeverityStats()
// Returns: map[severity]count

statsByReporter := vulns.SeverityStatsSetByReporter()
// Returns: map[reporter]SeverityStats
```

## Related

- [Core Package](../packages/core.md) - Vulnerability filtering
- [Severity Package](../packages/severity.md) - Statistics types
