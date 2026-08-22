package severity

import (
	"testing"
	"time"
)

// TestSLAStatusTimesString guards against status inversion: an item past its
// SLA days must report Out of SLA and an item within them must report
// Within SLA.
func TestSLAStatusTimesString(t *testing.T) {
	sla := SLAPolicy{CriticalDays: 15, HighDays: 30, MediumDays: 90, LowDays: 180}
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		severity string
		elapsed  int // days
		want     string
	}{
		{SeverityHigh, 10, StatusWithinSLA},
		{SeverityHigh, 60, StatusOutOfSLA},
		{SeverityCritical, 16, StatusOutOfSLA},
		{SeverityLow, 60, StatusWithinSLA},
	}
	for _, tt := range tests {
		eval := start.AddDate(0, 0, tt.elapsed)
		got, err := sla.SLAStatusTimesString(tt.severity, &start, eval, "Unknown")
		if err != nil {
			t.Fatalf("SLAStatusTimesString(%s, %dd): %v", tt.severity, tt.elapsed, err)
		}
		if got != tt.want {
			t.Errorf("SLAStatusTimesString(%s, %dd) = %s, want %s", tt.severity, tt.elapsed, got, tt.want)
		}
	}

	got, err := sla.SLAStatusTimesString(SeverityHigh, nil, start, "Unknown")
	if err != nil {
		t.Fatalf("SLAStatusTimesString(nil start): %v", err)
	}
	if got != "Unknown" {
		t.Errorf("SLAStatusTimesString(nil start) = %s, want Unknown", got)
	}
}
