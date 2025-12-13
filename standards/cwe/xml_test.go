package cwe

import (
	"testing"
)

var readFileTests = []struct {
	filename      string
	weaknessCount int
}{
	{"testdata/cwec_v4.15.xml", 964},
}

func TestReadFile(t *testing.T) {
	for _, tt := range readFileTests {
		xf, err := ReadFileXML(tt.filename)
		if err != nil {
			t.Errorf("cwe.ReadFile(\"%s\") error: (%s)", tt.filename, err.Error())
		}
		if tt.weaknessCount != len(xf.Weaknesses.Weakness) {
			t.Errorf("cwe.ReadFile(\"%s\") mismatch: want (%d), got (%d)", tt.filename, tt.weaknessCount, len(xf.Weaknesses.Weakness))
		}
	}
}
