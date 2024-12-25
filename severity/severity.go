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

func ParseSeverity(sev string) (string, error) {
	sev = strings.ToLower(strings.TrimSpace(sev))
	if sev == strings.ToLower(SeverityCritical) {
		return SeverityCritical, nil
	} else if sev == strings.ToLower(SeverityHigh) {
		return SeverityHigh, nil
	} else if sev == strings.ToLower(SeverityMedium) {
		return SeverityMedium, nil
	} else if sev == strings.ToLower(SeverityLow) {
		return SeverityLow, nil
	} else if sev == strings.ToLower(SeverityInformational) {
		return SeverityInformational, nil
	} else if sev == strings.ToLower(SeverityNone) {
		return SeverityNone, nil
	} else if sev == strings.ToLower(SeverityUnknown) {
		return SeverityUnknown, nil
	} else {
		return "", fmt.Errorf("severity not found (%s)", sev)
	}
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
	sev, err := ParseSeverity(sev)
	if err != nil {
		return sevs, sev, err
	}
	for i, si := range sevs {
		si, err := ParseSeverity(si)
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
