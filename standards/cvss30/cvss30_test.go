package cvss30

import (
	"testing"
)

var readFileTests = []struct {
	vectorString   string
	vectorMapCount int
}{
	{"CVSS:3.0/AV:L/AC:H/PR:l/UI:N/S:C/C:L/I:L/A:L/CR:H/IR:H/AR:L/MAV:L/MAC:H/MPR:H/MUI:N/MS:U/MC:L/MI:L/MA:L", 20},
}

func TestReadFile(t *testing.T) {
	for _, tt := range readFileTests {
		/*
			_, err := ParseVector(tt.vectorString)
			if err != nil {
				t.Errorf("cvss30.ParseVector(\"%s\") error: (%s)", tt.vectorString, err.Error())
			}
		*/
		vm, err := VectorToMap(tt.vectorString)
		if err != nil {
			t.Errorf("cvss30.VectorToMap(\"%s\") error: (%s)", tt.vectorString, err.Error())
		}
		if tt.vectorMapCount != len(vm) {
			t.Errorf("cvss30.VectorToMap(\"%s\") mismatch: want (%d), got (%d)", tt.vectorString, tt.vectorMapCount, len(vm))
		}
	}
}
