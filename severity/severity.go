package severity

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	// Common severities
	SeverityCritical      = "Critical"
	SeverityHigh          = "High"
	SeverityMedium        = "Medium"
	SeverityLow           = "Low"
	SeverityInformational = "Informational"
	SeverityNone          = "None"
	SeverityUnknown       = "Unknown"
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

func ParseSeverity(sev string) (string, Severity, error) {
	sev = strings.ToLower(strings.TrimSpace(sev))
	if sev == strings.ToLower(SeverityCritical) {
		return SeverityCritical, Critical, nil
	} else if sev == strings.ToLower(SeverityHigh) {
		return SeverityHigh, High, nil
	} else if sev == strings.ToLower(SeverityMedium) {
		return SeverityMedium, Medium, nil
	} else if sev == strings.ToLower(SeverityLow) {
		return SeverityLow, Low, nil
	} else if sev == strings.ToLower(SeverityInformational) {
		return SeverityInformational, Informational, nil
	} else if sev == strings.ToLower(SeverityNone) {
		return SeverityNone, None, nil
	} else if sev == strings.ToLower(SeverityUnknown) {
		return SeverityUnknown, Unknown, nil
	} else {
		return "", Unknown, fmt.Errorf("severity not found (%s)", sev)
	}
}

func ParseSeverities(sevs []string) ([]string, error) {
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
