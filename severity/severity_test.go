package severity

import (
	"slices"
	"strings"
	"testing"
)

var severitiesHigherTests = []struct {
	sevs      []string
	sev       string
	inclusive bool
	want      []string
}{
	{
		sevs:      SeveritiesAll(),
		sev:       SeverityHigh,
		inclusive: true,
		want:      []string{SeverityCritical, SeverityHigh},
	},
	{
		sevs:      SeveritiesAll(),
		sev:       SeverityHigh,
		inclusive: false,
		want:      []string{SeverityCritical},
	},
}

func TestSeveritiesHigher(t *testing.T) {
	for _, tt := range severitiesHigherTests {
		higher, err := SeveritiesHigher(tt.sevs, tt.sev, tt.inclusive)
		if err != nil {
			t.Errorf("severity.SeveritiesHigher() error (%s)", err.Error())
		} else if !slices.Equal(tt.want, higher) {
			t.Errorf("severity.SeveritiesHigher() Mismatch Error: want (%s), got (%s)",
				strings.Join(tt.want, ", "),
				strings.Join(higher, ", "))
		}
	}
}
