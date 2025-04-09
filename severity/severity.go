package severity

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	// Common severities
	SeverityCritical             = "Critical"
	SeverityHigh                 = "High"
	SeverityMedium               = "Medium"
	SeverityLow                  = "Low"
	SeverityInformational        = "Informational"
	SeverityNone                 = "None"
	SeverityUnknown              = "Unknown"
	SeverityPlusNeedsRemediation = "Needs Remediation"

	// Additional severities for parsing
	severityImportant = "Important" // > High: used by MS, aligned with High
	severityModerate  = "Moderate"  // > Medium: used by FedRAMP: https://www.fedramp.gov/assets/resources/documents/CSP_POAM_Template_Completion_Guide.pdf
	severityUntriaged = "Untriaged" // > Unknown: used by AWS Inspector: https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/inspector2/types#Severity
)

type Severity int

const (
	Critical Severity = iota
	High
	Medium
	Low
	Informational
	None
	Unknown
)

func (s Severity) IsHigher(sev Severity) bool { return s < sev }
func (s Severity) IsLower(sev Severity) bool  { return s > sev }
func (s Severity) IsEqual(sev Severity) bool  { return s == sev }
func (s Severity) NeedsRemediation() bool     { return s <= 3 }

// IsHigherString tests if `sev` is of higher severity than the refererence severity `refSev`.
func IsHigherString(sev, compSev string) (bool, error) {
	if sevInts, err := ParseSeverities([]string{sev, compSev}); err != nil {
		return false, err
	} else {
		return sevInts[0].IsHigher(sevInts[1]), nil
	}
}

// IsEqualString tests if `sev` is of equal severity to the refererence severity `refSev`.
func IsEqualString(sev, compSev string) (bool, error) {
	if sevInts, err := ParseSeverities([]string{sev, compSev}); err != nil {
		return false, err
	} else {
		return sevInts[0].IsEqual(sevInts[1]), nil
	}
}

// IsLowerString tests if `sev` is of lower severity than the refererence severity `refSev`.
func IsLowerString(sev, compSev string) (bool, error) {
	if sevInts, err := ParseSeverities([]string{sev, compSev}); err != nil {
		return false, err
	} else {
		return sevInts[0].IsLower(sevInts[1]), nil
	}
}

// ParseSeverity returns a canonical severity.
func ParseSeverity(sev string) (string, Severity, error) {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case strings.ToLower(SeverityCritical):
		return SeverityCritical, Critical, nil
	case strings.ToLower(SeverityHigh), strings.ToLower(severityImportant):
		return SeverityHigh, High, nil
	case strings.ToLower(SeverityMedium), strings.ToLower(severityModerate):
		return SeverityMedium, Medium, nil
	case strings.ToLower(SeverityLow):
		return SeverityLow, Low, nil
	case strings.ToLower(SeverityInformational):
		return SeverityInformational, Informational, nil
	case strings.ToLower(SeverityNone):
		return SeverityNone, None, nil
	case strings.ToLower(SeverityUnknown), strings.ToLower(severityUntriaged):
		return SeverityUnknown, Unknown, nil
	default:
		return "", Unknown, fmt.Errorf("severity not found (%s)", sev)
	}
}

func ParseSeverities(sevs []string) ([]Severity, error) {
	var out []Severity
	for _, sev := range sevs {
		if _, sevInt, err := ParseSeverity(sev); err != nil {
			return out, err
		} else {
			out = append(out, sevInt)
		}
	}
	if len(out) != len(sevs) {
		panic("internal error in severity.ParseSeverities - length mismatch")
	}
	return out, nil
}

func ParseSeveritiesString(sevs []string) ([]string, error) {
	var out []string
	for _, sev := range sevs {
		if sev, _, err := ParseSeverity(sev); err != nil {
			return out, err
		} else {
			out = append(out, sev)
		}
	}
	if len(out) != len(sevs) {
		panic("internal error in severity.ParseSeverities - length mismatch")
	}
	return out, nil
}

func SeveritiesFinding() []string {
	return []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
}

func SeveritiesAnalyzed() []string {
	return []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational, SeverityNone}
}

func SeveritiesAll() []string {
	return []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational, SeverityNone, SeverityUnknown}
}

// SeveritiesHigher returns a subset of the provided severities with elements
// that with a lower index than the provided severity. The provided severities
// mus be ranked from high to low.
func SeveritiesHigher(sevs []string, sev string, inclusive bool) ([]string, error) {
	sevs, sev, err := parseSeveritySliceIndexInfo(sevs, sev)
	if err != nil {
		return []string{}, err
	}
	var out []string
	for _, si := range sevs {
		if si == sev {
			if inclusive {
				out = append(out, si)
			}
			break
		} else {
			out = append(out, si)
		}
	}
	return out, nil
}

// SeveritiesLower returns a subset of the provided severities with elements
// that with a higher index than the provided severity. The provided severities
// mus be ranked from high to low.
func SeveritiesLower(sevs []string, sev string, inclusive bool) ([]string, error) {
	sevs, sev, err := parseSeveritySliceIndexInfo(sevs, sev)
	if err != nil {
		return []string{}, err
	}
	var out []string
	matched := false
	for _, si := range sevs {
		if si == sev {
			if inclusive {
				out = append(out, si)
			}
			matched = true
		} else if matched {
			out = append(out, si)
		}
	}
	return out, nil
}

func parseSeveritySliceIndexInfo(sevs []string, sev string) ([]string, string, error) {
	sev, _, err := ParseSeverity(sev)
	if err != nil {
		return sevs, sev, err
	}
	for i, si := range sevs {
		si, _, err := ParseSeverity(si)
		if err != nil {
			return sevs, sev, err
		}
		sevs[i] = si
	}
	if slices.Index(sevs, sev) < 0 {
		return sevs, sev, errors.New("severity not in slice")
	}
	return sevs, sev, nil
}

type MapBool map[string]bool

func NewMapBool(def bool) MapBool {
	return map[string]bool{
		SeverityCritical:      def,
		SeverityHigh:          def,
		SeverityMedium:        def,
		SeverityLow:           def,
		SeverityInformational: def,
		SeverityNone:          def,
		SeverityUnknown:       def,
	}
}

// AllTrueStrict checks if all severities are true. Strict checks
// that no additional severities are included in the map.
func (mb MapBool) AllTrue(strict bool) bool {
	sevs := SeveritiesAll()
	if strict && len(mb) != len(sevs) {
		return false
	}
	for _, sev := range sevs {
		if v, ok := mb[sev]; !ok || !v {
			return false
		}
	}
	return true
}

var mapSevNeedsRemediation = map[string]bool{
	SeverityCritical: true,
	SeverityHigh:     true,
	SeverityMedium:   true,
	SeverityLow:      true,
}

func NeedsRemediation(sev string) bool {
	sevConst, _, err := ParseSeverity(sev)
	sevTry := sevConst
	if err != nil {
		sevTry = sev
	}
	needs, ok := mapSevNeedsRemediation[sevTry]
	if !ok || ok && needs {
		return true
	} else {
		return false
	}
}

/*
func severityMap() map[string]string {
	return map[string]string{
		strings.ToLower(SeverityCritical):      SeverityCritical,
		strings.ToLower(SeverityHigh):          SeverityHigh,
		strings.ToLower(SeverityMedium):        SeverityMedium,
		strings.ToLower(SeverityLow):           SeverityLow,
		strings.ToLower(SeverityInformational): SeverityInformational,
		strings.ToLower(SeverityNone):          SeverityNone,
		strings.ToLower(SeverityUnknown):       SeverityUnknown,
	}
}
*/
