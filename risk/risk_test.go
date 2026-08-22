package risk

import (
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"critical", RiskCritical},
		{"Very High", RiskCritical},
		{"HIGH", RiskHigh},
		{"Moderate", RiskMedium},
		{"medium", RiskMedium},
		{"low", RiskLow},
		{"Negligible", RiskNegligible},
		{"very low", RiskNegligible},
	}
	for _, tt := range tests {
		got, err := ParseLevel(tt.in)
		if err != nil {
			t.Fatalf("ParseLevel(%s): %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("ParseLevel(%s) = %s, want %s", tt.in, got, tt.want)
		}
	}
	for _, invalid := range []string{"Informational", "None", "Unknown", ""} {
		if _, err := ParseLevel(invalid); err == nil {
			t.Errorf("ParseLevel(%s) should error: not a risk level", invalid)
		}
	}
}

func TestMatrixDefault(t *testing.T) {
	m := MatrixDefault()
	if err := m.Validate(); err != nil {
		t.Fatalf("MatrixDefault().Validate(): %v", err)
	}
	tests := []struct {
		likelihood string
		impact     string
		want       string
	}{
		{LevelHigh, LevelCritical, RiskCritical},
		{LevelHigh, LevelHigh, RiskCritical},
		{LevelLow, LevelHigh, RiskMedium},
		{LevelLow, LevelCritical, RiskHigh},
		{LevelVeryLow, LevelLow, RiskNegligible},
		{"low", "high", RiskMedium}, // case-insensitive axis labels
	}
	for _, tt := range tests {
		got, err := m.Rate(tt.likelihood, tt.impact)
		if err != nil {
			t.Fatalf("Rate(%s, %s): %v", tt.likelihood, tt.impact, err)
		}
		if got != tt.want {
			t.Errorf("Rate(%s, %s) = %s, want %s", tt.likelihood, tt.impact, got, tt.want)
		}
	}
	if _, err := m.Rate("Impossible", LevelHigh); err == nil {
		t.Error("Rate with unknown likelihood should error")
	}
	if _, err := m.Rate(LevelHigh, "Cosmic"); err == nil {
		t.Error("Rate with unknown impact should error")
	}
}

func TestScaleNISTSP80030RoundTrip(t *testing.T) {
	nist := ScaleNISTSP80030()
	pairs := []struct {
		canonical string
		nist      string
	}{
		{RiskCritical, "Very High"},
		{RiskHigh, "High"},
		{RiskMedium, "Moderate"},
		{RiskLow, "Low"},
		{RiskNegligible, "Very Low"},
	}
	for _, p := range pairs {
		label, err := nist.FromCanonical(p.canonical)
		if err != nil {
			t.Fatalf("FromCanonical(%s): %v", p.canonical, err)
		}
		if label != p.nist {
			t.Errorf("FromCanonical(%s) = %s, want %s", p.canonical, label, p.nist)
		}
		back, err := nist.ToCanonical(p.nist)
		if err != nil {
			t.Fatalf("ToCanonical(%s): %v", p.nist, err)
		}
		if back != p.canonical {
			t.Errorf("ToCanonical(%s) = %s, want %s", p.nist, back, p.canonical)
		}
	}
}

func TestRatingValidate(t *testing.T) {
	if err := (Rating{Rating: RiskMedium}).Validate(); err != nil {
		t.Errorf("Rating{Medium}.Validate(): %v", err)
	}
	if err := (Rating{Rating: "Informational"}).Validate(); err == nil {
		t.Error("Rating{Informational}.Validate() should error")
	}
}
