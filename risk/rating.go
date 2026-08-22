package risk

import (
	"fmt"
	"time"
)

// Rating is a qualitative risk assessment. Both inherent and residual risk
// use this type: inherent risk is assessed as if the relevant compensating
// controls did not exist, while residual risk is assessed given currently
// implemented, verified controls.
type Rating struct {
	Likelihood string     `json:"likelihood,omitempty"`
	Impact     string     `json:"impact,omitempty"`
	Rating     string     `json:"rating"`
	MatrixID   string     `json:"matrixId,omitempty"`
	Rationale  string     `json:"rationale,omitempty"`
	Confidence string     `json:"confidence,omitempty"`
	AssessedAt *time.Time `json:"assessedAt,omitempty"`
	AssessedBy string     `json:"assessedBy,omitempty"`
}

// Validate checks that the rating uses a canonical risk level.
func (r Rating) Validate() error {
	if _, err := ParseLevel(r.Rating); err != nil {
		return fmt.Errorf("risk rating invalid: %w", err)
	}
	return nil
}
