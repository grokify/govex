package severity

import (
	"slices"
	"strings"
	"testing"
)

var parseSeverityTests = []struct {
	v        string
	want     string
	wantIota Severity
}{
	{v: "CRITICAL", want: SeverityCritical, wantIota: Critical},
	{v: "important", want: SeverityHigh, wantIota: High},
	{v: "  moderate  ", want: SeverityMedium, wantIota: Medium},
}

func TestParseSeverity(t *testing.T) {
	for _, tt := range parseSeverityTests {
		sevStr, sevInt, err := ParseSeverity(tt.v)
		if err != nil {
			t.Errorf("severity.ParseSeverity(\"%s\") error (%s)", tt.v, err.Error())
		} else if sevStr != tt.want {
			t.Errorf("severity.ParseSeverity(\"%s\") Mismatch Error: want (%s), got (%s)",
				tt.v,
				tt.want,
				sevStr)
		} else if sevInt != tt.wantIota {
			t.Errorf("severity.ParseSeverity(\"%s\") Mismatch Error: want (%v), got (%v)",
				tt.v,
				tt.wantIota,
				sevInt)
		}
	}
}

var severitiesHigherLowerTests = []struct {
	sevs            []string
	sev             string
	inclusiveHigher bool
	inclusiveLower  bool
	wantHigher      []string
	wantLower       []string
}{
	{
		sevs:            SeveritiesAll(),
		sev:             SeverityMedium,
		inclusiveHigher: true,
		wantHigher:      []string{SeverityCritical, SeverityHigh, SeverityMedium},
		inclusiveLower:  false,
		wantLower:       []string{SeverityLow, SeverityInformational, SeverityNone, SeverityUnknown},
	},
	{
		sevs:            SeveritiesAll(),
		sev:             SeverityHigh,
		inclusiveHigher: true,
		wantHigher:      []string{SeverityCritical, SeverityHigh},
		inclusiveLower:  true,
		wantLower:       []string{SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational, SeverityNone, SeverityUnknown},
	},
	{
		sevs:            SeveritiesAll(),
		sev:             SeverityHigh,
		inclusiveHigher: false,
		wantHigher:      []string{SeverityCritical},
		inclusiveLower:  false,
		wantLower:       []string{SeverityMedium, SeverityLow, SeverityInformational, SeverityNone, SeverityUnknown},
	},
}

func TestSeveritiesHigherLower(t *testing.T) {
	for _, tt := range severitiesHigherLowerTests {
		higher, err := SeveritiesHigher(tt.sevs, tt.sev, tt.inclusiveHigher)
		if err != nil {
			t.Errorf("severity.SeveritiesHigher() error (%s)", err.Error())
		} else if !slices.Equal(tt.wantHigher, higher) {
			t.Errorf("severity.SeveritiesHigher() Mismatch Error: want (%s), got (%s)",
				strings.Join(tt.wantHigher, ", "),
				strings.Join(higher, ", "))
		}
		lower, err := SeveritiesLower(tt.sevs, tt.sev, tt.inclusiveLower)
		if err != nil {
			t.Errorf("severity.SeveritiesLower() error (%s)", err.Error())
		} else if !slices.Equal(tt.wantLower, lower) {
			t.Errorf("severity.SeveritiesLower() Mismatch Error: want (%s), got (%s)",
				strings.Join(tt.wantLower, ", "),
				strings.Join(higher, ", "))
		}
	}
}
