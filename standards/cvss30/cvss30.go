package cvss30

import (
	"errors"
	"strings"

	gocvss30 "github.com/pandatix/go-cvss/30"
)

type CVSS30 struct {
	V *gocvss30.CVSS30
}

type CVSS30Metric struct {
	Data   CVSS30Data   `json:"cvssData"`
	Scores CVSS30Scores `json:"cvssScores"`
}

type CVSS30Data struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

type CVSS30Scores struct {
	EnvironmentalScore  float64
	ExploitabilityScore float64
	ImpactScore         float64
	TemporalScore       float64
}

func (v CVSS30) Data() (CVSS30Metric, error) {
	if v.V == nil {
		return CVSS30Metric{}, errors.New("vector not set")
	}
	return CVSS30Metric{
		Data: CVSS30Data{
			Version:      "3.0",
			BaseScore:    v.V.BaseScore(),
			VectorString: v.V.Vector(),
		},
		Scores: CVSS30Scores{
			EnvironmentalScore:  v.V.EnvironmentalScore(),
			ExploitabilityScore: v.V.Exploitability(),
			ImpactScore:         v.V.Impact(),
			TemporalScore:       v.V.TemporalScore(),
		},
	}, nil
}

func ParseVector(v string) (CVSS30, error) {
	gv, err := gocvss30.ParseVector(v)
	if err != nil {
		return CVSS30{}, err
	}
	return CVSS30{V: gv}, nil
}

// ParseAttackVectorAbbr returns the description for an abbreviation.
// https://www.first.org/cvss/v2.0/specification-document
// https://www.first.org/cvss/v3.0/specification-document
// https://www.first.org/cvss/v3.1/specification-document
// https://www.first.org/cvss/v4.0/specification-document
// https://qualysguard.qg2.apps.qualys.com/qwebhelp/fo_portal/setup/cvss_vector_strings.htm
// https://source.whitehatsec.com/help/sentinel/secops/cvssv3-factors.html
func ParseAttackVectorAbbr(abbr string) (string, error) {
	m := map[string]string{
		"N": "Network",
		"A": "Adjacent",
		"L": "Local",
		"P": "Physical"}
	if v, ok := m[abbr]; ok {
		return v, nil
	} else {
		return "", errors.New("no match")
	}
}

func VectorToMap(v string) (map[string]string, error) {
	out := map[string]string{}
	v = strings.TrimSpace(v)
	p := strings.Split(v, "/")
	for _, p1 := range p {
		p2 := strings.Split(p1, ":")
		if len(p2) != 2 {
			return out, errors.New("invalid format")
		}
		out[p2[0]] = p2[1]
	}
	return out, nil
}

/*
func VectorToData(v string) (CVSS30Data, error) {
	d := CVSS30Data{}
	return d, nil
}
*/
