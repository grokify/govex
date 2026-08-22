# CVSS Support

Support for Common Vulnerability Scoring System (CVSS).

## Installation

```go
import "github.com/grokify/govex/standards/cvss30"
```

## Supported Versions

| Version | Support |
|---------|---------|
| CVSS 3.0 | Full |
| CVSS 3.1 | Full |
| CVSS 4.0 | Partial |

## Usage

### Parse CVSS Vector

```go
score, err := cvss30.ParseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
if err != nil {
    log.Fatal(err)
}

fmt.Println("Base Score:", score.BaseScore())
fmt.Println("Severity:", score.Severity())
```

### Calculate Score

```go
// From vector components
score := cvss30.Score{
    AttackVector:       "Network",
    AttackComplexity:   "Low",
    PrivilegesRequired: "None",
    UserInteraction:    "None",
    Scope:              "Unchanged",
    Confidentiality:    "High",
    Integrity:          "High",
    Availability:       "High",
}

base := score.Calculate()
```

## Qualitative Severity Rating Scales

GoVEX aligns with the [NVD qualitative severity ratings](https://nvd.nist.gov/vuln-metrics/cvss). The rating bands are version-specific and provided by the `cvss` package:

```go
import "github.com/grokify/govex/cvss"

set, err := cvss.SeveritySetForVersion("3.1") // accepts "2.0", "3.0", "3.1", "3.x", "4.0"
sev, err := set.SeverityFromScoreFloat32(3.9) // "Low"
```

### CVSS v3.x and v4.0

CVSS v3.0, v3.1, and v4.0 share the same rating bands:

| Score Range | Rating |
|-------------|--------|
| 0.0 | None |
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |

### CVSS v2.0

CVSS v2.0 defines no None or Critical rating; Low starts at 0.0 and High extends to 10.0:

| Score Range | Rating |
|-------------|--------|
| 0.0 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 10.0 | High |

!!! warning "Do not relabel v2 scores with v3/v4 bands"
    A CVSS v2.0 score of 9.8 is **High** under the v2 scale. It must not be relabeled Critical unless re-derived from a v3.x or v4.0 vector. Use `cvss.SeveritySetCVSS2()` for legacy v2-scored data.

### Base vs. Environmental Severity

The base score yields the **inherent** severity. A CVSS environmental score — the base metrics modified by verified compensating controls (e.g. `MAV:A` for network segmentation) — yields the **residual** severity, using the same rating bands. See [Compensating Controls & Residual Risk](../reference/residual-risk.md).

## Vector String Format

CVSS 3.1 vector format:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Values |
|--------|--------|
| AV (Attack Vector) | N (Network), A (Adjacent), L (Local), P (Physical) |
| AC (Attack Complexity) | L (Low), H (High) |
| PR (Privileges Required) | N (None), L (Low), H (High) |
| UI (User Interaction) | N (None), R (Required) |
| S (Scope) | U (Unchanged), C (Changed) |
| C (Confidentiality) | N (None), L (Low), H (High) |
| I (Integrity) | N (None), L (Low), H (High) |
| A (Availability) | N (None), L (Low), H (High) |

## Related

- [CVE Support](cve.md)
- [Severity Package](../packages/severity.md)
