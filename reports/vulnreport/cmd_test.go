package vulnreport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestSetFile(t *testing.T) string {
	t.Helper()
	r := testReport()
	dir := t.TempDir()
	filename := filepath.Join(dir, "vulns.json")
	if err := r.Set.WriteFileJSON(filename, "", "  ", 0600); err != nil {
		t.Fatalf("writing set file: %v", err)
	}
	return filename
}

func TestReadReportOrSetFile(t *testing.T) {
	setFile := writeTestSetFile(t)
	r, err := ReadReportOrSetFile(setFile)
	if err != nil {
		t.Fatalf("ReadReportOrSetFile(set): %v", err)
	}
	if r.Set == nil || len(r.Set.Vulnerabilities) != 2 {
		t.Fatal("ReadReportOrSetFile(set) did not load vulnerabilities")
	}
	if r.Title != "example-app scan" {
		t.Errorf("Title = %q, want set name", r.Title)
	}

	reportFile := filepath.Join(t.TempDir(), "report.json")
	if err := testReport().WriteJSONFile(reportFile, 0600); err != nil {
		t.Fatalf("writing report file: %v", err)
	}
	r2, err := ReadReportOrSetFile(reportFile)
	if err != nil {
		t.Fatalf("ReadReportOrSetFile(report): %v", err)
	}
	if r2.Title != "Q3 Vulnerability Report" || r2.Organization != "Example Corp" {
		t.Error("ReadReportOrSetFile(report) did not preserve report metadata")
	}

	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, []byte(`{"foo": "bar"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReportOrSetFile(badFile); err == nil {
		t.Error("ReadReportOrSetFile(bad) should error")
	}
}

func TestCmdReportCobraHTML(t *testing.T) {
	setFile := writeTestSetFile(t)
	outFile := filepath.Join(t.TempDir(), "report.html")

	c := CmdReportCobra("")
	c.SetArgs([]string{
		"--input", setFile,
		"--output", outFile,
		"--title", "CLI Report",
		"--classification", "Internal",
		"--columns", "residual",
	})
	if err := c.Execute(); err != nil {
		t.Fatalf("Execute(): %v", err)
	}

	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	h := string(b)
	for _, want := range []string{
		"<title>CLI Report</title>",
		`<div class="classification">Internal</div>`,
		"Residual Severity",
		"CVE-2026-12345",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML output missing %q", want)
		}
	}
}

func TestCmdReportUnsupportedOutput(t *testing.T) {
	opts := CmdReportOptions{
		InputFilename:  writeTestSetFile(t),
		OutputFilename: filepath.Join(t.TempDir(), "report.docx"),
	}
	if err := opts.Run(); err == nil {
		t.Error("Run() with .docx output should error")
	}

	opts.OutputFilename = filepath.Join(t.TempDir(), "report.html")
	opts.Columns = "bogus"
	if err := opts.Run(); err == nil {
		t.Error("Run() with bogus columns should error")
	}
}
