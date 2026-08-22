# Risk Package

The `risk` package provides organization-level risk ratings, explicit risk matrices, and scale translation, including NIST SP 800-30. Risk ratings share the canonical severity vocabulary (Critical, High, Medium, Low) but are derived from a likelihood × impact matrix rather than a CVSS score.

## Installation

```go
import "github.com/grokify/govex/risk"
```

## Risk Levels

Canonical risk levels, ordered high to low:

| Level | Notes |
|-------|-------|
| `RiskCritical` | Shares the severity vocabulary |
| `RiskHigh` | |
| `RiskMedium` | |
| `RiskLow` | |
| `RiskNegligible` | Risk-only floor for residual risk backed by verified controls; no severity counterpart |

Informational, None, and Unknown are severity concepts and are **not** valid risk levels; `ParseLevel` rejects them.

```go
level, err := risk.ParseLevel("Moderate") // "Medium" — NIST vocabulary accepted as alias
levels := risk.Levels()                   // Critical, High, Medium, Low
all := risk.LevelsWithNegligible()        // + Negligible
```

## Ratings

A `Rating` is a qualitative risk assessment used for both inherent and residual risk:

```go
rating := risk.Rating{
    Likelihood: risk.LevelLow,
    Impact:     risk.LevelHigh,
    Rating:     risk.RiskMedium,
    MatrixID:   "govex-default-4x4",
    Rationale:  "Verified segmentation prevents access from identified threat actors.",
    Confidence: "high",
}

err := rating.Validate()
```

Inherent risk is assessed as if the relevant compensating controls did not exist; residual risk is assessed given currently implemented, verified controls. See [Compensating Controls & Residual Risk](../reference/residual-risk.md).

## Risk Matrices

The rating for a likelihood × impact combination is an organizational policy choice, not a calculation, so the matrix is an explicit object referenced by ID:

```go
m := risk.MatrixDefault() // common 4×4 matrix

rating, err := m.Rate(risk.LevelLow, risk.LevelCritical) // "High"
err = m.Validate() // every cell must be a canonical risk level
```

Define your own matrix to encode your organization's policy — for example, whether low likelihood × high impact is Low or Medium:

```go
m := risk.Matrix{
    ID: "acme-3x3",
    Lookup: map[string]map[string]string{
        risk.LevelHigh: {
            risk.LevelLow:  risk.RiskMedium,
            risk.LevelHigh: risk.RiskCritical,
        },
        // ...
    },
}
```

## Scales

Ratings are always stored canonically; a `Scale` relabels them for rendering:

```go
def := risk.ScaleDefault()       // govex canonical vocabulary
nist := risk.ScaleNISTSP80030()  // NIST SP 800-30 vocabulary

label, err := nist.FromCanonical(risk.RiskMedium) // "Moderate"
level, err := nist.ToCanonical("Very High")       // "Critical"
```

## NIST SP 800-30 Translation

NIST SP 800-30 Rev. 1 levels map 1:1 to the canonical scale:

| Canonical | NIST SP 800-30 | Semi-Quantitative Range | Representative Value |
|-----------|----------------|-------------------------|----------------------|
| Critical | Very High | 96 - 100 | 10 |
| High | High | 80 - 95 | 8 |
| Medium | Moderate | 21 - 79 | 5 |
| Low | Low | 5 - 20 | 2 |
| Negligible | Very Low | 0 - 4 | 0 |

The semi-quantitative values are NIST's published 0-100 assessment scale (SP 800-30 Rev. 1 Appendix G/H/I). They are **not** CVSS scores; the two must not be conflated.

```go
// Level translation
nist, err := risk.ToNIST80030(risk.RiskCritical)  // "Very High"
level, err := risk.FromNIST80030("Moderate")      // "Medium"

// Semi-quantitative values
v, err := risk.NIST80030ValueFromScore(87)        // High (80-95, representative 8)
v, err = risk.NIST80030ValueFromLevel("Medium")   // Moderate entry; accepts either vocabulary

// Translate a whole rating for FedRAMP-style rendering
out, err := risk.TranslateRatingToNIST80030(rating)
// out.Rating: "Moderate", out.Likelihood: "Low", out.Impact translated;
// rationale, matrix ID, and assessor fields pass through unchanged
```

Store ratings canonically and translate at the report boundary — `TranslateRatingToNIST80030` never mutates its input.

## Related

- [Compensating Controls & Residual Risk](../reference/residual-risk.md) - Conceptual model and SLA policy
- [Core Package](core.md) - Vulnerability types carrying `RiskInherent` and `RiskResidual`
- [Severity Package](severity.md) - Severity classification and SLA policies
