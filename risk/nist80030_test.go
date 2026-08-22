package risk

import (
	"testing"
)

func TestNIST80030Translators(t *testing.T) {
	pairs := []struct {
		canonical string
		nist      string
	}{
		{RiskCritical, NIST80030VeryHigh},
		{RiskHigh, NIST80030High},
		{RiskMedium, NIST80030Moderate},
		{RiskLow, NIST80030Low},
		{RiskNegligible, NIST80030VeryLow},
	}
	for _, p := range pairs {
		nist, err := ToNIST80030(p.canonical)
		if err != nil {
			t.Fatalf("ToNIST80030(%s): %v", p.canonical, err)
		}
		if nist != p.nist {
			t.Errorf("ToNIST80030(%s) = %s, want %s", p.canonical, nist, p.nist)
		}
		back, err := FromNIST80030(p.nist)
		if err != nil {
			t.Fatalf("FromNIST80030(%s): %v", p.nist, err)
		}
		if back != p.canonical {
			t.Errorf("FromNIST80030(%s) = %s, want %s", p.nist, back, p.canonical)
		}
	}
	if _, err := ToNIST80030("Informational"); err == nil {
		t.Error("ToNIST80030(Informational) should error: not a risk level")
	}
}

func TestNIST80030ValueFromScore(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, NIST80030VeryHigh},
		{96, NIST80030VeryHigh},
		{95, NIST80030High},
		{80, NIST80030High},
		{79, NIST80030Moderate},
		{21, NIST80030Moderate},
		{20, NIST80030Low},
		{5, NIST80030Low},
		{4, NIST80030VeryLow},
		{0, NIST80030VeryLow},
	}
	for _, tt := range tests {
		v, err := NIST80030ValueFromScore(tt.score)
		if err != nil {
			t.Fatalf("NIST80030ValueFromScore(%d): %v", tt.score, err)
		}
		if v.Level != tt.want {
			t.Errorf("NIST80030ValueFromScore(%d) = %s, want %s", tt.score, v.Level, tt.want)
		}
	}
	for _, invalid := range []int{-1, 101} {
		if _, err := NIST80030ValueFromScore(invalid); err == nil {
			t.Errorf("NIST80030ValueFromScore(%d) should error", invalid)
		}
	}
}

func TestNIST80030ValueFromLevel(t *testing.T) {
	// Accepts both NIST and canonical vocabulary.
	for _, level := range []string{NIST80030Moderate, RiskMedium} {
		v, err := NIST80030ValueFromLevel(level)
		if err != nil {
			t.Fatalf("NIST80030ValueFromLevel(%s): %v", level, err)
		}
		if v.RepresentativeValue != 5 {
			t.Errorf("NIST80030ValueFromLevel(%s).RepresentativeValue = %d, want 5", level, v.RepresentativeValue)
		}
	}
}

func TestTranslateRatingToNIST80030(t *testing.T) {
	r := Rating{
		Likelihood: LevelLow,
		Impact:     LevelCritical,
		Rating:     RiskMedium,
		MatrixID:   "govex-default-4x4",
		Rationale:  "Verified segmentation prevents external access.",
	}
	out, err := TranslateRatingToNIST80030(r)
	if err != nil {
		t.Fatalf("TranslateRatingToNIST80030: %v", err)
	}
	if out.Rating != NIST80030Moderate {
		t.Errorf("Rating = %s, want %s", out.Rating, NIST80030Moderate)
	}
	if out.Likelihood != NIST80030Low {
		t.Errorf("Likelihood = %s, want %s", out.Likelihood, NIST80030Low)
	}
	if out.Impact != NIST80030VeryHigh {
		t.Errorf("Impact = %s, want %s", out.Impact, NIST80030VeryHigh)
	}
	if out.Rationale != r.Rationale || out.MatrixID != r.MatrixID {
		t.Error("non-level fields should pass through unchanged")
	}
	// Canonical original must be unchanged: translate at the report boundary.
	if r.Rating != RiskMedium {
		t.Error("input rating mutated")
	}
}
