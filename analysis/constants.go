package analysis

import (
	"fmt"
	"strings"
)

type ImpactAnalysisState string

const (
	FieldEvidence      = "evidence"
	FieldJustification = "justification"
	FieldState         = "state"

	IASAffected           ImpactAnalysisState = "affected"
	IASFixed              ImpactAnalysisState = "fixed"
	IASNotAffected        ImpactAnalysisState = "not_affected"
	IASNotStarted         ImpactAnalysisState = "not_started"
	IASUnderInvestigation ImpactAnalysisState = "under_investigation"
)

func ParseImpactAnalysisState(s string, blankState ImpactAnalysisState) (ImpactAnalysisState, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "_")
	switch s {
	case string(IASAffected):
		return IASAffected, nil
	case string(IASFixed):
		return IASFixed, nil
	case string(IASNotAffected):
		return IASNotAffected, nil
	case string(IASNotStarted):
		return IASNotStarted, nil
	case string(IASUnderInvestigation):
		return IASUnderInvestigation, nil
	case "":
		return blankState, nil
	default:
		return "", fmt.Errorf("state not known (%s)", s)
	}
}
