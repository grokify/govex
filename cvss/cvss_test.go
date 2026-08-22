package cvss

import (
	"testing"

	"github.com/grokify/govex/severity"
)

var severityFromScoreTests = []struct {
	version string
	score   float32
	want    string
}{
	// CVSS v2.0: no None or Critical; Low starts at 0.0, High ends at 10.0.
	{Version20, 0.0, severity.SeverityLow},
	{Version20, 3.9, severity.SeverityLow},
	{Version20, 4.0, severity.SeverityMedium},
	{Version20, 6.9, severity.SeverityMedium},
	{Version20, 7.0, severity.SeverityHigh},
	{Version20, 9.8, severity.SeverityHigh},
	{Version20, 10.0, severity.SeverityHigh},
	// CVSS v3.x per NVD: None 0.0, Low 0.1-3.9, Medium 4.0-6.9,
	// High 7.0-8.9, Critical 9.0-10.0.
	{Version3x, 0.0, severity.SeverityNone},
	{Version3x, 0.1, severity.SeverityLow},
	{Version3x, 3.9, severity.SeverityLow},
	{Version3x, 4.0, severity.SeverityMedium},
	{Version3x, 6.9, severity.SeverityMedium},
	{Version3x, 7.0, severity.SeverityHigh},
	{Version3x, 8.9, severity.SeverityHigh},
	{Version3x, 9.0, severity.SeverityCritical},
	{Version3x, 10.0, severity.SeverityCritical},
	// CVSS v4.0 uses the same ranges as v3.x.
	{Version40, 0.0, severity.SeverityNone},
	{Version40, 3.9, severity.SeverityLow},
	{Version40, 4.0, severity.SeverityMedium},
	{Version40, 8.9, severity.SeverityHigh},
	{Version40, 9.0, severity.SeverityCritical},
}

func TestSeverityFromScore(t *testing.T) {
	for _, tt := range severityFromScoreTests {
		set, err := SeveritySetForVersion(tt.version)
		if err != nil {
			t.Fatalf("SeveritySetForVersion(%s): %v", tt.version, err)
		}
		got, err := set.SeverityFromScoreFloat32(tt.score)
		if err != nil {
			t.Fatalf("SeverityFromScoreFloat32(v%s, %v): %v", tt.version, tt.score, err)
		}
		if got != tt.want {
			t.Errorf("SeverityFromScoreFloat32(v%s, %v) = %s, want %s", tt.version, tt.score, got, tt.want)
		}
	}
}

func TestSeveritySetForVersionAliases(t *testing.T) {
	for _, alias := range []string{"3.0", "3.1", "3", "3.x"} {
		set, err := SeveritySetForVersion(alias)
		if err != nil {
			t.Fatalf("SeveritySetForVersion(%s): %v", alias, err)
		}
		if set.Version != Version3x {
			t.Errorf("SeveritySetForVersion(%s).Version = %s, want %s", alias, set.Version, Version3x)
		}
	}
	if _, err := SeveritySetForVersion("5.0"); err == nil {
		t.Error("SeveritySetForVersion(5.0) should error")
	}
}

func TestSeverityFromScoreUnclassified(t *testing.T) {
	set := SeveritySetCVSS4()
	if _, err := set.SeverityFromScoreFloat32(11.0); err == nil {
		t.Error("SeverityFromScoreFloat32(11.0) should error")
	}
	// CVSS v2.0 has no Critical rating; a v2-scored 9.8 must remain High
	// and must not be relabeled using v3/v4 ranges.
	got, err := SeveritySetCVSS2().SeverityFromScoreFloat32(9.8)
	if err != nil {
		t.Fatalf("SeverityFromScoreFloat32(v2, 9.8): %v", err)
	}
	if got != severity.SeverityHigh {
		t.Errorf("SeverityFromScoreFloat32(v2, 9.8) = %s, want %s", got, severity.SeverityHigh)
	}
}
