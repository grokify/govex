package vex

import (
	"fmt"
	"strings"
)

const (
	SeverityCritical      = "Critical"
	SeverityHigh          = "High"
	SeverityMedium        = "Medium"
	SeverityLow           = "Low"
	SeverityInformational = "Informational"
	SeverityUnknown       = "Unknown"
	SeverityNone          = "None"
)

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

func SeveritySliceFinding() []string {
	return []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
}

func SeveritySliceAnalyzed() []string {
	return []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational, SeverityNone}
}

func SeveritySliceAll() []string {
	return []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational, SeverityNone, SeverityUnknown}
}
