package risk

import (
	"fmt"
	"strings"
)

// NIST SP 800-30 Rev. 1 qualitative assessment levels, used for likelihood,
// impact, and risk in its Appendix G, H, and I assessment scales. These map
// 1:1 to the canonical govex risk levels: Very High↔Critical, High↔High,
// Moderate↔Medium, Low↔Low, Very Low↔Negligible.
const (
	NIST80030VeryHigh = "Very High"
	NIST80030High     = "High"
	NIST80030Moderate = "Moderate"
	NIST80030Low      = "Low"
	NIST80030VeryLow  = "Very Low"
)

// NIST80030Levels returns the NIST SP 800-30 qualitative levels, ordered
// high to low, parallel to LevelsWithNegligible.
func NIST80030Levels() []string {
	return []string{NIST80030VeryHigh, NIST80030High, NIST80030Moderate, NIST80030Low, NIST80030VeryLow}
}

// NIST80030Value is a NIST SP 800-30 Rev. 1 assessment level with the
// standard's published semi-quantitative values: a 0-100 range and a single
// representative value (10, 8, 5, 2, 0). This is NIST's assessment scale,
// not a CVSS score; the two 0-10 lookalikes must not be conflated.
type NIST80030Value struct {
	Level               string `json:"level"`
	CanonicalLevel      string `json:"canonicalLevel"`
	SemiQuantMin        int    `json:"semiQuantMin"`
	SemiQuantMax        int    `json:"semiQuantMax"`
	RepresentativeValue int    `json:"representativeValue"`
}

// NIST80030Values returns the NIST SP 800-30 Rev. 1 assessment levels with
// semi-quantitative values, ordered high to low.
func NIST80030Values() []NIST80030Value {
	return []NIST80030Value{
		{Level: NIST80030VeryHigh, CanonicalLevel: RiskCritical, SemiQuantMin: 96, SemiQuantMax: 100, RepresentativeValue: 10},
		{Level: NIST80030High, CanonicalLevel: RiskHigh, SemiQuantMin: 80, SemiQuantMax: 95, RepresentativeValue: 8},
		{Level: NIST80030Moderate, CanonicalLevel: RiskMedium, SemiQuantMin: 21, SemiQuantMax: 79, RepresentativeValue: 5},
		{Level: NIST80030Low, CanonicalLevel: RiskLow, SemiQuantMin: 5, SemiQuantMax: 20, RepresentativeValue: 2},
		{Level: NIST80030VeryLow, CanonicalLevel: RiskNegligible, SemiQuantMin: 0, SemiQuantMax: 4, RepresentativeValue: 0},
	}
}

// NIST80030ValueFromScore returns the assessment level for a NIST SP 800-30
// semi-quantitative score on the 0-100 scale.
func NIST80030ValueFromScore(score int) (NIST80030Value, error) {
	for _, v := range NIST80030Values() {
		if score >= v.SemiQuantMin && score <= v.SemiQuantMax {
			return v, nil
		}
	}
	return NIST80030Value{}, fmt.Errorf("nist sp 800-30 semi-quantitative score out of range 0-100 (%d)", score)
}

// NIST80030ValueFromLevel returns the assessment level with semi-quantitative
// values for a NIST SP 800-30 or canonical level label.
func NIST80030ValueFromLevel(level string) (NIST80030Value, error) {
	canonical, err := ParseLevel(level)
	if err != nil {
		return NIST80030Value{}, err
	}
	for _, v := range NIST80030Values() {
		if v.CanonicalLevel == canonical {
			return v, nil
		}
	}
	return NIST80030Value{}, fmt.Errorf("nist sp 800-30 level not found (%s)", level)
}

// ToNIST80030 translates a canonical govex risk level to its NIST SP 800-30
// label, e.g. Critical → Very High, Negligible → Very Low.
func ToNIST80030(canonicalLevel string) (string, error) {
	return ScaleNISTSP80030().FromCanonical(canonicalLevel)
}

// FromNIST80030 translates a NIST SP 800-30 label to the canonical govex
// risk level, e.g. Moderate → Medium, Very Low → Negligible.
func FromNIST80030(nistLevel string) (string, error) {
	return ScaleNISTSP80030().ToCanonical(nistLevel)
}

// TranslateRatingToNIST80030 returns a copy of the rating with its rating,
// likelihood, and impact labels translated to NIST SP 800-30 vocabulary for
// rendering in FedRAMP-style exports. The canonical rating should remain the
// stored form; translate at the report boundary.
func TranslateRatingToNIST80030(r Rating) (Rating, error) {
	out := r
	if strings.TrimSpace(r.Rating) != "" {
		rating, err := ToNIST80030(r.Rating)
		if err != nil {
			return out, fmt.Errorf("rating: %w", err)
		}
		out.Rating = rating
	}
	if strings.TrimSpace(r.Likelihood) != "" {
		likelihood, err := ToNIST80030(r.Likelihood)
		if err != nil {
			return out, fmt.Errorf("likelihood: %w", err)
		}
		out.Likelihood = likelihood
	}
	if strings.TrimSpace(r.Impact) != "" {
		impact, err := ToNIST80030(r.Impact)
		if err != nil {
			return out, fmt.Errorf("impact: %w", err)
		}
		out.Impact = impact
	}
	return out, nil
}
