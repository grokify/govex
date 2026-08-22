// Package vulnreport renders a VulnerabilitiesSet as a titled report in
// Markdown, HTML, and PDF. The VulnerabilitiesSet remains the data IR; this
// package adds report-level metadata (title, author, classification, period)
// and presentation.
package vulnreport

import (
	"encoding/json"
	"os"
	"strconv"
	"time"

	"github.com/grokify/gocharts/v2/data/table"

	"github.com/grokify/govex"
	"github.com/grokify/govex/severity"
)

// Report is a titled vulnerability report over a VulnerabilitiesSet.
type Report struct {
	Title          string     `json:"title"`
	Subtitle       string     `json:"subtitle,omitempty"`
	Organization   string     `json:"organization,omitempty"`
	Author         string     `json:"author,omitempty"`
	Classification string     `json:"classification,omitempty"` // e.g. "Confidential"
	GeneratedAt    *time.Time `json:"generatedAt,omitempty"`
	PeriodStart    *time.Time `json:"periodStart,omitempty"`
	PeriodEnd      *time.Time `json:"periodEnd,omitempty"`
	Summary        string     `json:"summary,omitempty"` // executive summary

	Set *govex.VulnerabilitiesSet `json:"set,omitempty"`

	// ColumnSet defines the findings table columns; when nil,
	// DefaultColumnDefinitionSet is used.
	ColumnSet *table.ColumnDefinitionSet `json:"-"`
}

// NewReport returns a report over the provided set.
func NewReport(title string, set *govex.VulnerabilitiesSet) *Report {
	return &Report{Title: title, Set: set}
}

// Vulnerabilities returns the report's vulnerabilities; nil-safe.
func (r *Report) Vulnerabilities() govex.Vulnerabilities {
	if r.Set == nil {
		return govex.Vulnerabilities{}
	}
	return r.Set.Vulnerabilities
}

// DefaultColumnDefinitionSet returns findings table columns suited to
// rendered reports: plain-text names without Markdown link syntax.
func DefaultColumnDefinitionSet() table.ColumnDefinitionSet {
	return table.ColumnDefinitionSet{
		DefaultFormat: table.FormatString,
		Definitions: []table.ColumnDefinition{
			{Name: govex.FieldSeverity, SourceName: govex.FieldSeverity, DefaultValue: severity.SeverityUnknown},
			{Name: govex.FieldID, SourceName: govex.FieldID},
			{Name: govex.FieldName, SourceName: govex.FieldName},
			{Name: govex.FieldCategory, SourceName: govex.FieldCategory},
			{Name: govex.FieldLibraryName, SourceName: govex.FieldLibraryName},
			{Name: govex.FieldLibraryVersion, SourceName: govex.FieldLibraryVersion},
			{Name: govex.FieldLibraryVersionFixed, SourceName: govex.FieldLibraryVersionFixed},
		},
	}
}

// ResidualColumnDefinitionSet returns findings table columns for reports
// showing inherent vs. residual assessments with compensating controls.
// Set Vulnerability.ProcSLAEvalTime for time-sensitive effective severity.
func ResidualColumnDefinitionSet() table.ColumnDefinitionSet {
	return table.ColumnDefinitionSet{
		DefaultFormat: table.FormatString,
		Definitions: []table.ColumnDefinition{
			{Name: govex.FieldID, SourceName: govex.FieldID},
			{Name: govex.FieldName, SourceName: govex.FieldName},
			{Name: govex.FieldSeverity, SourceName: govex.FieldSeverity, DefaultValue: severity.SeverityUnknown},
			{Name: govex.FieldSeverityResidual, SourceName: govex.FieldSeverityResidual},
			{Name: govex.FieldRiskResidual, SourceName: govex.FieldRiskResidual},
			{Name: govex.FieldExceptionStatus, SourceName: govex.FieldExceptionStatus},
			{Name: govex.FieldControls, SourceName: govex.FieldControls},
		},
	}
}

func (r *Report) columnSet() table.ColumnDefinitionSet {
	if r.ColumnSet != nil {
		return *r.ColumnSet
	}
	return DefaultColumnDefinitionSet()
}

func (r *Report) valueOptions() *govex.ValueOptions {
	if r.Set != nil {
		return r.Set.VulnValueOpts
	}
	return nil
}

// FindingsTable returns the findings table using the report's column set.
func (r *Report) FindingsTable() (*table.Table, error) {
	vulns := r.Vulnerabilities()
	tbl, err := vulns.Table(r.columnSet(), r.valueOptions())
	if err != nil {
		return nil, err
	}
	tbl.Name = "Findings"
	return tbl, nil
}

// SeverityTable returns a severity count summary ordered Critical to Unknown,
// omitting zero-count severities, with a Total row.
func (r *Report) SeverityTable() *table.Table {
	vulns := r.Vulnerabilities()
	hist := vulns.SeverityHistogram()
	tbl := table.NewTable("Severity Summary")
	tbl.Columns = []string{"Severity", "Count"}
	tbl.FormatMap = map[int]string{1: table.FormatInt}
	total := 0
	for _, sev := range severity.SeveritiesAll() {
		count, ok := hist.Items[sev]
		if !ok || count == 0 {
			continue
		}
		tbl.Rows = append(tbl.Rows, []string{sev, strconv.Itoa(count)})
		total += count
	}
	tbl.Rows = append(tbl.Rows, []string{"Total", strconv.Itoa(total)})
	return &tbl
}

// findingDetail is the per-finding block rendered after the findings table
// in HTML and Markdown output. All fields are plain text; each renderer
// applies its own escaping.
type findingDetail struct {
	ID               string
	Name             string
	Severity         string
	RiskInherent     string
	SeverityResidual string
	RiskResidual     string
	Description      string
	Controls         []controlDetail
}

type controlDetail struct {
	Name        string
	Description string
	Verified    bool
}

func (r *Report) findingDetails() []findingDetail {
	var details []findingDetail
	for _, vn := range r.Vulnerabilities() {
		d := findingDetail{
			ID:               vn.ID,
			Name:             vn.Name,
			Severity:         vn.Severity,
			SeverityResidual: vn.SeverityResidual,
			Description:      vn.Description,
		}
		if d.Name == "" {
			d.Name = govex.NameUnnamedVulerability
		}
		if vn.RiskInherent != nil {
			d.RiskInherent = vn.RiskInherent.Rating
		}
		if vn.RiskResidual != nil {
			d.RiskResidual = vn.RiskResidual.Rating
		}
		for _, ctrl := range vn.Controls {
			d.Controls = append(d.Controls, controlDetail{
				Name:        ctrl.Name,
				Description: ctrl.Description,
				Verified:    ctrl.Verified,
			})
		}
		details = append(details, d)
	}
	return details
}

// metaField is a label/value pair rendered in the report header block.
type metaField struct {
	Label string
	Value string
}

func (r *Report) metaFields() []metaField {
	var fields []metaField
	add := func(label, value string) {
		if value != "" {
			fields = append(fields, metaField{Label: label, Value: value})
		}
	}
	add("Organization", r.Organization)
	add("Author", r.Author)
	add("Classification", r.Classification)
	if r.GeneratedAt != nil {
		add("Generated", r.GeneratedAt.Format(time.DateOnly))
	}
	add("Period", r.periodString())
	if r.Set != nil {
		add("Source", r.Set.Name)
		add("Repository", r.Set.RepoURL)
		if r.Set.DateTime != nil {
			add("Data As Of", r.Set.DateTime.Format(time.DateOnly))
		}
	}
	add("Findings", strconv.Itoa(len(r.Vulnerabilities())))
	return fields
}

func (r *Report) periodString() string {
	switch {
	case r.PeriodStart != nil && r.PeriodEnd != nil:
		return r.PeriodStart.Format(time.DateOnly) + " to " + r.PeriodEnd.Format(time.DateOnly)
	case r.PeriodStart != nil:
		return "from " + r.PeriodStart.Format(time.DateOnly)
	case r.PeriodEnd != nil:
		return "through " + r.PeriodEnd.Format(time.DateOnly)
	default:
		return ""
	}
}

// JSON returns the report as indented JSON.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// WriteJSONFile writes the report as JSON.
func (r *Report) WriteJSONFile(filename string, perm os.FileMode) error {
	b, err := r.JSON()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, b, perm)
}

// ReadFile reads a JSON report file.
func ReadFile(filename string) (*Report, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	r := Report{}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
