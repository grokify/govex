package vulnreport

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/grokify/gocharts/v2/data/table"

	"github.com/grokify/govex"
	"github.com/grokify/govex/risk"
	"github.com/grokify/govex/severity"
)

func testReport() *Report {
	gen := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	set := govex.NewVulnerabilitiesSet()
	set.Name = "example-app scan"
	set.RepoURL = "https://github.com/example/app"
	set.Vulnerabilities = govex.Vulnerabilities{
		{
			ID:       "CVE-2026-12345",
			Name:     "SQL Injection in login <form>",
			Severity: severity.SeverityHigh,
			Category: govex.CategorySAST,
		},
		{
			ID:       "CVE-2026-23456",
			Name:     "Outdated crypto library",
			Severity: severity.SeverityMedium,
			Category: govex.CategorySCA,
			Library:  govex.Library{Name: "libcrypto", Version: "1.0.0", VersionFixed: "1.0.9"},
		},
	}
	r := NewReport("Q3 Vulnerability Report", set)
	r.Subtitle = "Example App"
	r.Organization = "Example Corp"
	r.Author = "Security Team"
	r.Classification = "Confidential"
	r.GeneratedAt = &gen
	r.Summary = "Two findings were identified.\n\nRemediation is on track."
	return r
}

func TestReportMarkdown(t *testing.T) {
	r := testReport()
	md, err := r.Markdown()
	if err != nil {
		t.Fatalf("Markdown(): %v", err)
	}
	// The table renderer pads cells for column alignment; collapse runs of
	// spaces so assertions are padding-agnostic.
	md = regexp.MustCompile(` +`).ReplaceAllString(md, " ")
	for _, want := range []string{
		"# Q3 Vulnerability Report",
		"**Confidential**",
		"- **Organization:** Example Corp",
		"## Executive Summary",
		"## Severity Summary",
		"## Findings",
		"CVE-2026-12345",
		"| High | 1 |",
		"| Total | 2 |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown() missing %q", want)
		}
	}
}

func TestReportMarkdownFindingDetails(t *testing.T) {
	r := testReport()
	r.Set.Vulnerabilities[0].Description = "User input reaches the query builder unsanitized."
	r.Set.Vulnerabilities[0].SeverityResidual = severity.SeverityLow
	r.Set.Vulnerabilities[0].RiskInherent = &risk.Rating{Rating: risk.RiskHigh}
	r.Set.Vulnerabilities[0].RiskResidual = &risk.Rating{Rating: risk.RiskLow}
	r.Set.Vulnerabilities[0].Controls = []govex.CompensatingControl{
		{Name: "Parameterized query gateway", Description: "All queries pass through a parameterizing proxy.", Verified: true},
	}
	md, err := r.Markdown()
	if err != nil {
		t.Fatalf("Markdown(): %v", err)
	}
	for _, want := range []string{
		"## Finding Details",
		"### SQL Injection in login <form>",
		"- **ID:** CVE-2026-12345",
		"- **Severity:** High",
		"- **Inherent Risk:** High",
		"- **Residual Severity:** Low",
		"- **Residual Risk:** Low",
		"User input reaches the query builder unsanitized.",
		"#### Compensating Controls",
		"- **Parameterized query gateway**: All queries pass through a parameterizing proxy. *(verified)*",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown() missing %q", want)
		}
	}
	// Findings without residual data omit those items and the controls heading
	// appears only once.
	if got := strings.Count(md, "#### Compensating Controls"); got != 1 {
		t.Errorf("Markdown() has %d control subsections, want 1", got)
	}
	if got := strings.Count(md, "- **Residual Severity:**"); got != 1 {
		t.Errorf("Markdown() has %d residual severity items, want 1", got)
	}
}

func TestReportHTML(t *testing.T) {
	r := testReport()
	r.Set.Vulnerabilities[0].Description = "User input reaches the query builder <script>unescaped</script>."
	r.Set.Vulnerabilities[0].SeverityResidual = severity.SeverityLow
	r.Set.Vulnerabilities[0].RiskInherent = &risk.Rating{Rating: risk.RiskHigh}
	r.Set.Vulnerabilities[0].RiskResidual = &risk.Rating{Rating: risk.RiskLow}
	r.Set.Vulnerabilities[0].Controls = []govex.CompensatingControl{
		{Name: "Parameterized query gateway", Description: "All queries pass through a parameterizing proxy.", Verified: true},
	}
	h, err := r.HTML()
	if err != nil {
		t.Fatalf("HTML(): %v", err)
	}
	for _, want := range []string{
		"<title>Q3 Vulnerability Report</title>",
		`<div class="classification">Confidential</div>`,
		"<h2>Severity Summary</h2>",
		"CVE-2026-12345",
		"SQL Injection in login &lt;form&gt;", // cell values HTML-escaped
		"<h2>Finding Details</h2>",
		"<h3>SQL Injection in login &lt;form&gt;</h3>",
		"<dt>Residual Severity</dt><dd>Low</dd>",
		"<dt>Inherent Risk</dt><dd>High</dd>",
		"<dt>Residual Risk</dt><dd>Low</dd>",
		"<h4>Compensating Controls</h4>",
		"<strong>Parameterized query gateway</strong>: All queries pass through a parameterizing proxy. <em>(verified)</em>",
		"&lt;script&gt;unescaped&lt;/script&gt;", // description HTML-escaped
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML() missing %q", want)
		}
	}
	for _, reject := range []string{"<form>", "<script>"} {
		if strings.Contains(h, reject) {
			t.Errorf("HTML() contains unescaped value %q", reject)
		}
	}
	// A finding without controls gets no controls subsection; count occurrences.
	if got := strings.Count(h, "<h4>Compensating Controls</h4>"); got != 1 {
		t.Errorf("HTML() has %d control subsections, want 1", got)
	}
}

func TestReportPDF(t *testing.T) {
	r := testReport()
	b, err := r.PDF()
	if err != nil {
		t.Fatalf("PDF(): %v", err)
	}
	if len(b) == 0 {
		t.Fatal("PDF() returned empty bytes")
	}
	if !strings.HasPrefix(string(b[:5]), "%PDF-") {
		t.Errorf("PDF() output missing %%PDF- header, got %q", string(b[:5]))
	}
}

func TestReportPDFTooManyColumns(t *testing.T) {
	r := testReport()
	defs := make([]table.ColumnDefinition, 13)
	for i := range defs {
		defs[i] = table.ColumnDefinition{Name: govex.FieldID, SourceName: govex.FieldID}
	}
	r.ColumnSet = &table.ColumnDefinitionSet{Definitions: defs}
	if _, err := r.PDF(); err == nil {
		t.Error("PDF() with 13 columns should error")
	}
}

func TestReportEmptySet(t *testing.T) {
	r := NewReport("Empty Report", nil)
	md, err := r.Markdown()
	if err != nil {
		t.Fatalf("Markdown() on nil set: %v", err)
	}
	if !strings.Contains(md, "No findings.") {
		t.Error("Markdown() on nil set should report no findings")
	}
	if _, err := r.HTML(); err != nil {
		t.Fatalf("HTML() on nil set: %v", err)
	}
	if _, err := r.PDF(); err != nil {
		t.Fatalf("PDF() on nil set: %v", err)
	}
}

func TestPDFColumnWidths(t *testing.T) {
	tests := []struct {
		n    int
		want []int
	}{
		{1, []int{12}},
		{2, []int{6, 6}},
		{5, []int{3, 3, 2, 2, 2}},
		{7, []int{2, 2, 2, 2, 2, 1, 1}},
		{12, []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
	}
	for _, tt := range tests {
		got := pdfColumnWidths(tt.n)
		sum := 0
		for i, w := range got {
			sum += w
			if w != tt.want[i] {
				t.Errorf("pdfColumnWidths(%d) = %v, want %v", tt.n, got, tt.want)
				break
			}
		}
		if sum != 12 {
			t.Errorf("pdfColumnWidths(%d) sums to %d, want 12", tt.n, sum)
		}
	}
}

func TestResidualColumnSet(t *testing.T) {
	r := testReport()
	r.Set.Vulnerabilities[0].SeverityResidual = severity.SeverityLow
	r.Set.Vulnerabilities[0].Controls = []govex.CompensatingControl{
		{ID: "CTRL-001", Name: "Network segmentation"},
	}
	r.Set.Vulnerabilities[0].Exception = &govex.ExceptionStatus{Status: govex.ExceptionStatusApproved}
	cols := ResidualColumnDefinitionSet()
	r.ColumnSet = &cols

	md, err := r.Markdown()
	if err != nil {
		t.Fatalf("Markdown(): %v", err)
	}
	md = regexp.MustCompile(` +`).ReplaceAllString(md, " ")
	for _, want := range []string{
		"Residual Severity",
		"Exception Status",
		"Network segmentation",
		"Approved",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown() with residual columns missing %q", want)
		}
	}

	// 7 columns fits the PDF grid.
	if _, err := r.PDF(); err != nil {
		t.Fatalf("PDF() with residual columns: %v", err)
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	r := testReport()
	b, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON(): %v", err)
	}
	if !strings.Contains(string(b), `"title": "Q3 Vulnerability Report"`) {
		t.Error("JSON() missing title")
	}
}
