package cve20

import (
	"fmt"
	"strings"
)

type Metrics struct {
	// CvssMetricV40 []CvssMetricV40 `json:"cvssMetricV40,omitempty"`
	// ref: https://pkg.go.dev/github.com/aquasecurity/trivy-db/pkg/vulnsrc/nvd#CvssDataV30
	CVSSMetricV31 []CVSSMetricV3 `json:"cvssMetricV31,omitempty"`
	CVSSMetricV30 []CVSSMetricV3 `json:"cvssMetricV30,omitempty"`
	CVSSMetricV2  []CVSSMetricV2 `json:"cvssMetricV2,omitempty"`
}

func NewMetrics() Metrics {
	return Metrics{
		CVSSMetricV31: []CVSSMetricV3{},
		CVSSMetricV30: []CVSSMetricV3{},
		CVSSMetricV2:  []CVSSMetricV2{}}
}

func (m *Metrics) AppendMetrics(more Metrics) {
	m.CVSSMetricV31 = append(m.CVSSMetricV31, more.CVSSMetricV31...)
	m.CVSSMetricV30 = append(m.CVSSMetricV30, more.CVSSMetricV30...)
	m.CVSSMetricV2 = append(m.CVSSMetricV2, more.CVSSMetricV2...)
}

func (m *Metrics) AppendCVSSMetricV3(more CVSSMetricV3) {
	if more.CVSSData.Version == "3.1" {
		m.CVSSMetricV31 = append(m.CVSSMetricV31, more)
	} else {
		m.CVSSMetricV30 = append(m.CVSSMetricV30, more)
	}
}

type CVSSMetricV3 struct {
	Source   string     `json:"source"`
	Type     string     `json:"type"`
	CVSSData CVSSDataV3 `json:"cvssData"`
}

type CVSSDataV3 struct {
	Version               string `json:"version"`
	VectorString          string `json:"vectorString,omitempty"`
	AttackVector          string `json:"attackVector,omitempty"`
	AttackComplexity      string `json:"attackComplexity,omitempty"`
	PrivilegesRequired    string `json:"privilegesRequired,omitempty"`
	UserInteraction       string `json:"userInteraction,omitempty"`
	Scope                 string `json:"scope,omitempty"`
	ConfidentialityImpact string `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       string `json:"integrityImpact,omitempty"`
	AvailabilityImpact    string `json:"availabilityImpact,omitempty"`
	BaseScore             string `json:"baseScore,omitempty"`
	BaseSeverity          string `json:"baseSeverity,omitempty"`
}

func (cvss *CVSSDataV3) SetVectorString(v string) {
	cvss.VectorString = strings.ToUpper(strings.TrimSpace(v))
	parts := strings.Split(cvss.VectorString, "/")
	defs := CVSSMetricDefinitions()
	for _, p := range parts {
		p2 := strings.Split(p, ":")
		if len(p2) != 2 {
			continue
		}
		k := p2[0]
		v := p2[1]
		if k == "CVSS" {
			cvss.Version = v
		} else if def, ok := defs[k]; ok {
			if val, ok := def.Values[v]; ok {
				val = strings.ToUpper(val)
				switch k {
				case "AV":
					cvss.AttackVector = val
				case "AC":
					cvss.AttackComplexity = val
				case "PR":
					cvss.PrivilegesRequired = val
				case "UI":
					cvss.UserInteraction = val
				case "S":
					cvss.Scope = val
				case "C":
					cvss.ConfidentialityImpact = val
				case "I":
					cvss.IntegrityImpact = val
				case "A":
					cvss.AvailabilityImpact = val
				default:
					panic(fmt.Sprintf("CVSS VAR VAL not found K(%s) V(%s)", k, v))
				}
			}
		} else {
			panic(fmt.Sprintf("CVSS VAR not found K(%s) V(%s)", k, v))
		}
	}
}

type CVSSMetricDefinition struct {
	Abbr    string
	Display string
	Values  map[string]string
}

func CVSSMetricDefinitions() map[string]CVSSMetricDefinition {
	// ref: https://qualysguard.qg2.apps.qualys.com/qwebhelp/fo_portal/setup/cvss_vector_strings.htm
	// ref: VectorString: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
	m := map[string]CVSSMetricDefinition{
		"AV": {
			Abbr:    "AV",
			Display: "Attack Vector",
			Values: map[string]string{
				"N": "Network",
				"A": "Adjacent Network",
				"L": "Local",
				"P": "Physical",
			},
		},
		"AC": {
			Abbr:    "AC",
			Display: "Attack Complexity",
			Values: map[string]string{
				"H": "High",
				"L": "Low",
			},
		},
		"PR": {
			Abbr:    "PR",
			Display: "Privileges Required",
			Values: map[string]string{
				"H": "High",
				"L": "Low",
				"N": "None",
			},
		},
		"UI": {
			Abbr:    "UI",
			Display: "User Interaction",
			Values: map[string]string{
				"R": "Required",
				"N": "None",
			},
		},
		"S": {
			Abbr:    "S",
			Display: "Scope",
			Values: map[string]string{
				"C": "Changed",
				"U": "Unchanged",
			},
		},
		"C": {
			Abbr:    "C",
			Display: "Confidentiality Impact",
			Values: map[string]string{
				"H": "High",
				"L": "Low",
				"N": "None",
			},
		},
		"I": {
			Abbr:    "I",
			Display: "Integrity Impact",
			Values: map[string]string{
				"H": "High",
				"L": "Low",
				"N": "None",
			},
		},
		"A": {
			Abbr:    "A",
			Display: "Availability Impact",
			Values: map[string]string{
				"H": "High",
				"L": "Low",
				"N": "None",
			},
		},
	}
	return m
}

type CVSSMetricV2 struct {
	Source string `json:"source"`
	Type   string `json:"type"`
}
