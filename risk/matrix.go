package risk

import (
	"fmt"
	"strings"
)

// Matrix is an explicit likelihood × impact risk matrix. The rating for a
// given likelihood and impact combination is an organizational policy choice,
// not a calculation, so the matrix must be stated explicitly and referenced
// by ID from ratings it produced.
type Matrix struct {
	ID     string                       `json:"id"`
	Lookup map[string]map[string]string `json:"lookup"` // likelihood → impact → rating
}

// Rate returns the risk rating for a likelihood and impact combination.
// Axis labels are matched case-insensitively.
func (m Matrix) Rate(likelihood, impact string) (string, error) {
	for lk, row := range m.Lookup {
		if !strings.EqualFold(strings.TrimSpace(likelihood), lk) {
			continue
		}
		for ik, rating := range row {
			if strings.EqualFold(strings.TrimSpace(impact), ik) {
				return rating, nil
			}
		}
		return "", fmt.Errorf("impact not in matrix %s (%s)", m.ID, impact)
	}
	return "", fmt.Errorf("likelihood not in matrix %s (%s)", m.ID, likelihood)
}

// Validate checks that every cell holds a canonical risk level.
func (m Matrix) Validate() error {
	for lk, row := range m.Lookup {
		for ik, rating := range row {
			if _, err := ParseLevel(rating); err != nil {
				return fmt.Errorf("matrix %s cell (%s, %s): %w", m.ID, lk, ik, err)
			}
		}
	}
	return nil
}

// MatrixDefault returns a common 4×4 risk matrix. Organizations should
// define their own matrix; this default caps how far low likelihood can
// pull down the rating for high-impact scenarios.
func MatrixDefault() Matrix {
	return Matrix{
		ID: "govex-default-4x4",
		Lookup: map[string]map[string]string{
			LevelHigh: {
				LevelLow:      RiskMedium,
				LevelMedium:   RiskHigh,
				LevelHigh:     RiskCritical,
				LevelCritical: RiskCritical,
			},
			LevelMedium: {
				LevelLow:      RiskLow,
				LevelMedium:   RiskMedium,
				LevelHigh:     RiskHigh,
				LevelCritical: RiskCritical,
			},
			LevelLow: {
				LevelLow:      RiskLow,
				LevelMedium:   RiskLow,
				LevelHigh:     RiskMedium,
				LevelCritical: RiskHigh,
			},
			LevelVeryLow: {
				LevelLow:      RiskNegligible,
				LevelMedium:   RiskLow,
				LevelHigh:     RiskLow,
				LevelCritical: RiskMedium,
			},
		},
	}
}
