package cve20

import (
	"fmt"
	"strings"

	"github.com/grokify/mogo/pointer"
	"github.com/relvacode/iso8601"
)

const (
	BaseSeverityCritical = "CRITICAL"
	BaseSeverityHigh     = "HIGH"
	BaseSeverityMedium   = "MEDIUM"
	BaseSeverityLow      = "LOW"
	BaseSeverityNone     = "NONE"

	// https://nvd.nist.gov/vuln/vulnerability-status
	VulnStatusAnalyzed = "Analyzed"
	VulnStatusModified = "Modified"

	TypePrimary       = "Primary"
	TypeSecondary     = "Secondary"
	CVSSDataVersion31 = "3.1"
	OperatorOr        = "OR"
)

type CVE struct {
	ID               string          `json:"id,omitempty"`
	SourceIdentifier string          `json:"sourceIdentifier,omitempty"`
	VulnStatus       string          `json:"vulnStatus,omitempty"`
	Published        *iso8601.Time   `json:"published,omitempty"`
	LastModified     *iso8601.Time   `json:"lastModified,omitempty"`
	Metrics          Metrics         `json:"metrics,omitempty"`
	Descriptions     []Description   `json:"descriptions,omitempty"`
	Weaknesses       []Weakness      `json:"weaknesses,omitempty"`
	CVETags          []string        `json:"cveTags,omitempty"`
	Configurations   []Configuration `json:"configurations,omitempty"`
}

type Description struct {
	Lang  string `json:"lang,omitempty"`
	Title string `json:"subject,omitempty"`
	Value string `json:"value,omitempty"`
}

func (c *CVE) AddDescription(title, desc, lang, app, versionEndExcluding string) {
	title = strings.TrimSpace(title)
	desc = strings.TrimSpace(desc)
	lang = strings.TrimSpace(lang)
	app = strings.TrimSpace(app)
	versionEndExcluding = strings.TrimSpace(versionEndExcluding)
	d := Description{
		Lang:  lang,
		Title: title,
	}
	if versionEndExcluding != "" {
		if app != "" {
			f := "An issue was discovered in %s before %s. %s"
			desc = fmt.Sprintf(f, app, versionEndExcluding, desc)
		}
	}
	d.Value = desc
	c.Descriptions = append(c.Descriptions, d)
}

func (c *CVE) AddMetric31(source, cveType, baseSeverity string) {
	baseSeverity = strings.TrimSpace(baseSeverity)
	if baseSeverity == "" {
		return
	}
	c.Metrics.CVSSMetricV31 = append(c.Metrics.CVSSMetricV31,
		CVSSMetricV3{
			Source: source,
			Type:   cveType,
			CVSSData: CVSSDataV3{
				Version:      CVSSDataVersion31,
				BaseSeverity: baseSeverity,
			},
		},
	)
}

func (c *CVE) AddConfiguration(versionEndExcluding string) {
	versionEndExcluding = strings.TrimSpace(versionEndExcluding)
	if versionEndExcluding == "" {
		return
	}
	c.Configurations = append(c.Configurations,
		Configuration{
			Nodes: []Node{{
				Operator: OperatorOr,
				Negate:   pointer.Pointer(false),
				CPEMatch: []CPEMatch{
					{
						Vulnerable:          pointer.Pointer(true),
						VersionEndExcluding: versionEndExcluding,
					},
				},
			}},
		},
	)
}

type Configuration struct {
	Nodes []Node `json:"nodes,omitempty"`
}

type Node struct {
	Operator string     `json:"operator,omitempty"`
	Negate   *bool      `json:"negate"`
	CPEMatch []CPEMatch `json:"cpeMatch,omitempty"`
}

type CPEMatch struct {
	Vulnerable          *bool  `json:"vulnerable"`
	VersionEndExcluding string `json:"versionEndExcluding,omitempty"`
}

type Weakness struct {
	Source      string        `json:"source,omitempty"`
	Type        string        `json:"type,omitempty"`
	Description []Description `json:"descriptions,omitempty"`
}
