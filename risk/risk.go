// Package risk provides organization-level risk ratings, risk matrices, and
// scale mappings for inherent and residual risk assessments. Risk ratings
// share the canonical severity vocabulary (Critical, High, Medium, Low) but
// are derived from a likelihood × impact matrix rather than a CVSS score.
package risk

import (
	"fmt"
	"strings"

	"github.com/grokify/govex/severity"
)

// Canonical risk rating levels, ordered high to low. These reuse the
// severity vocabulary so risk and severity columns sort and compare
// consistently. Negligible is a risk-only floor for residual risk backed by
// verified controls; it has no severity counterpart. Informational, None,
// and Unknown are severity concepts and are not valid risk levels.
const (
	RiskCritical   = severity.SeverityCritical
	RiskHigh       = severity.SeverityHigh
	RiskMedium     = severity.SeverityMedium
	RiskLow        = severity.SeverityLow
	RiskNegligible = "Negligible"
)

// Likelihood and impact axis levels for risk matrices.
const (
	LevelCritical = "Critical"
	LevelVeryHigh = "Very High"
	LevelHigh     = "High"
	LevelMedium   = "Medium"
	LevelLow      = "Low"
	LevelVeryLow  = "Very Low"
)

// Levels returns the canonical risk rating levels, ordered high to low,
// excluding the optional Negligible floor.
func Levels() []string {
	return []string{RiskCritical, RiskHigh, RiskMedium, RiskLow}
}

// LevelsWithNegligible returns the canonical risk rating levels including
// the Negligible floor, ordered high to low.
func LevelsWithNegligible() []string {
	return []string{RiskCritical, RiskHigh, RiskMedium, RiskLow, RiskNegligible}
}

// ParseLevel returns a canonical risk rating level, accepting NIST SP 800-30
// vocabulary (Very High, Moderate, Very Low) as aliases.
func ParseLevel(level string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case strings.ToLower(RiskCritical), strings.ToLower(LevelVeryHigh):
		return RiskCritical, nil
	case strings.ToLower(RiskHigh):
		return RiskHigh, nil
	case strings.ToLower(RiskMedium), "moderate":
		return RiskMedium, nil
	case strings.ToLower(RiskLow):
		return RiskLow, nil
	case strings.ToLower(RiskNegligible), strings.ToLower(LevelVeryLow):
		return RiskNegligible, nil
	default:
		return "", fmt.Errorf("risk level not found (%s)", level)
	}
}
