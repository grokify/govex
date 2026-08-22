package risk

import (
	"fmt"
	"strings"
)

// Scale is a named risk rating vocabulary. Ratings are always stored
// canonically (Critical, High, Medium, Low, Negligible); scales relabel
// them for rendering, e.g. NIST SP 800-30 vocabulary for FedRAMP-style
// exports. Levels are ordered high to low, parallel to
// LevelsWithNegligible.
type Scale struct {
	ID     string   `json:"id"`
	Levels []string `json:"levels"`
}

// ScaleDefault returns the canonical govex risk scale.
func ScaleDefault() Scale {
	return Scale{
		ID:     "govex-default",
		Levels: LevelsWithNegligible(),
	}
}

// ScaleNISTSP80030 returns the NIST SP 800-30 Rev. 1 assessment scale.
// It maps 1:1 to the canonical scale: Very High↔Critical, High↔High,
// Moderate↔Medium, Low↔Low, Very Low↔Negligible.
func ScaleNISTSP80030() Scale {
	return Scale{
		ID:     "nist-sp-800-30",
		Levels: NIST80030Levels(),
	}
}

// FromCanonical returns this scale's label for a canonical risk level.
func (s Scale) FromCanonical(level string) (string, error) {
	level, err := ParseLevel(level)
	if err != nil {
		return "", err
	}
	for i, canonical := range LevelsWithNegligible() {
		if canonical == level {
			if i >= len(s.Levels) {
				return "", fmt.Errorf("scale %s has no label for level (%s)", s.ID, level)
			}
			return s.Levels[i], nil
		}
	}
	return "", fmt.Errorf("risk level not found (%s)", level)
}

// ToCanonical returns the canonical risk level for one of this scale's labels.
func (s Scale) ToCanonical(label string) (string, error) {
	for i, l := range s.Levels {
		if strings.EqualFold(strings.TrimSpace(label), l) {
			canonical := LevelsWithNegligible()
			if i >= len(canonical) {
				return "", fmt.Errorf("scale %s label out of range (%s)", s.ID, label)
			}
			return canonical[i], nil
		}
	}
	return "", fmt.Errorf("label not in scale %s (%s)", s.ID, label)
}
