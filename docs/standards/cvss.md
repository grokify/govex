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

## Severity Ratings

| Score Range | Rating |
|-------------|--------|
| 0.0 | None |
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |

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
