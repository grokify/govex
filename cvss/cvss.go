// Package cvss provides CVSS qualitative severity rating scales aligned with
// the NVD published ranges: https://nvd.nist.gov/vuln-metrics/cvss .
package cvss

import (
	"fmt"
	"strings"

	"github.com/grokify/govex/severity"
	"github.com/shopspring/decimal"
)

// CVSS version identifiers for qualitative severity rating scales.
// CVSS v3.0 and v3.1 share one scale, as do v4.0 and later.
const (
	Version20 = "2.0"
	Version3x = "3.x"
	Version40 = "4.0"
)

type Severity struct {
	Name string
	Min  decimal.Decimal
	Max  decimal.Decimal
}

type SeveritySet struct {
	Version string
	Map     map[string]Severity
}

// SeveritySetCVSS2 returns the CVSS v2.0 qualitative severity rating scale.
// CVSS v2.0 defines no None or Critical rating: Low begins at 0.0 and
// High extends to 10.0.
func SeveritySetCVSS2() SeveritySet {
	return SeveritySet{
		Version: Version20,
		Map: map[string]Severity{
			severity.SeverityHigh: {
				Name: severity.SeverityHigh,
				Min:  decimal.RequireFromString("7.0"),
				Max:  decimal.RequireFromString("10.0")},
			severity.SeverityMedium: {
				Name: severity.SeverityMedium,
				Min:  decimal.RequireFromString("4.0"),
				Max:  decimal.RequireFromString("6.9")},
			severity.SeverityLow: {
				Name: severity.SeverityLow,
				Min:  decimal.RequireFromString("0.0"),
				Max:  decimal.RequireFromString("3.9")},
		},
	}
}

// SeveritySetCVSS3x returns the CVSS v3.0/v3.1 qualitative severity rating scale.
func SeveritySetCVSS3x() SeveritySet {
	set := severitySetCVSS3Plus()
	set.Version = Version3x
	return set
}

// SeveritySetCVSS4 returns the CVSS v4.0 qualitative severity rating scale,
// which uses the same ranges as CVSS v3.x.
func SeveritySetCVSS4() SeveritySet {
	set := severitySetCVSS3Plus()
	set.Version = Version40
	return set
}

func severitySetCVSS3Plus() SeveritySet {
	return SeveritySet{
		Map: map[string]Severity{
			severity.SeverityCritical: {
				Name: severity.SeverityCritical,
				Min:  decimal.RequireFromString("9.0"),
				Max:  decimal.RequireFromString("10.0")},
			severity.SeverityHigh: {
				Name: severity.SeverityHigh,
				Min:  decimal.RequireFromString("7.0"),
				Max:  decimal.RequireFromString("8.9")},
			severity.SeverityMedium: {
				Name: severity.SeverityMedium,
				Min:  decimal.RequireFromString("4.0"),
				Max:  decimal.RequireFromString("6.9")},
			severity.SeverityLow: {
				Name: severity.SeverityLow,
				Min:  decimal.RequireFromString("0.1"),
				Max:  decimal.RequireFromString("3.9")},
			severity.SeverityNone: {
				Name: severity.SeverityNone,
				Min:  decimal.RequireFromString("0.0"),
				Max:  decimal.RequireFromString("0.0")},
		},
	}
}

// SeveritySetForVersion returns the qualitative severity rating scale for a
// CVSS version string such as "2.0", "3.0", "3.1", "3.x", or "4.0".
func SeveritySetForVersion(version string) (SeveritySet, error) {
	switch strings.TrimSpace(version) {
	case Version20, "2":
		return SeveritySetCVSS2(), nil
	case Version3x, "3", "3.0", "3.1":
		return SeveritySetCVSS3x(), nil
	case Version40, "4":
		return SeveritySetCVSS4(), nil
	default:
		return SeveritySet{}, fmt.Errorf("cvss version not supported (%s)", version)
	}
}

// SeverityFromScore returns the qualitative severity rating for a score.
// Scores must have at most one decimal place of precision, as published;
// values falling between rating ranges (e.g. 0.05 on v3.x) are an error.
func (set SeveritySet) SeverityFromScore(score decimal.Decimal) (string, error) {
	for _, sev := range set.Map {
		if score.Cmp(sev.Min) >= 0 && score.Cmp(sev.Max) <= 0 {
			return sev.Name, nil
		}
	}
	return severity.SeverityUnknown,
		fmt.Errorf("score not classified for cvss version %s (%s)", set.Version, score.String())
}

// SeverityFromScoreFloat32 returns the qualitative severity rating for a score.
func (set SeveritySet) SeverityFromScoreFloat32(score float32) (string, error) {
	return set.SeverityFromScore(decimal.NewFromFloat32(score))
}

// SeverityFromScoreFloat64 returns the qualitative severity rating for a score.
func (set SeveritySet) SeverityFromScoreFloat64(score float64) (string, error) {
	return set.SeverityFromScore(decimal.NewFromFloat(score))
}
