// Command example generates an example vulnerability report in Markdown,
// HTML, and PDF.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/grokify/govex"
	"github.com/grokify/govex/reports/vulnreport"
	"github.com/grokify/govex/risk"
	"github.com/grokify/govex/severity"
)

func main() {
	r := example()
	outputs := []struct {
		filename string
		write    func(string, os.FileMode) error
	}{
		{"vulnreport_example.md", r.WriteMarkdownFile},
		{"vulnreport_example.html", r.WriteHTMLFile},
		{"vulnreport_example.pdf", r.WritePDFFile},
		{"vulnreport_example.json", r.WriteJSONFile},
	}
	for _, out := range outputs {
		if err := out.write(out.filename, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", out.filename, err)
			os.Exit(1)
		}
		fmt.Printf("Wrote %s\n", out.filename)
	}
}

func example() *vulnreport.Report {
	gen := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	set := govex.NewVulnerabilitiesSet()
	set.Name = "example-app security scan"
	set.RepoURL = "https://github.com/example/app"
	set.DateTime = &gen
	set.Vulnerabilities = govex.Vulnerabilities{
		{
			ID:               "CVE-2026-12345",
			Name:             "SQL Injection in login form",
			Description:      "User-supplied input reaches the login query without parameterization, permitting SQL injection.",
			Severity:         severity.SeverityHigh,
			SeverityResidual: severity.SeverityLow,
			RiskInherent:     &risk.Rating{Rating: risk.RiskHigh},
			RiskResidual:     &risk.Rating{Rating: risk.RiskLow, Rationale: "Verified parameterizing proxy blocks injection payloads."},
			Controls: []govex.CompensatingControl{
				{
					ID:          "CTRL-001",
					Name:        "Parameterized query gateway",
					Description: "All database queries pass through a parameterizing proxy that rejects raw SQL fragments.",
					Verified:    true,
				},
			},
			Category: govex.CategorySAST,
		},
		{
			ID:          "CVE-2026-23456",
			Name:        "Outdated cryptographic library",
			Description: "The bundled libcrypto version is past end of life and misses multiple security patches.",
			Severity:    severity.SeverityMedium,
			Category:    govex.CategorySCA,
			Library:     govex.Library{Name: "libcrypto", Version: "1.0.0", VersionFixed: "1.0.9"},
		},
		{
			ID:          "CVE-2026-34567",
			Name:        "Verbose error messages",
			Description: "Stack traces are returned to end users on unhandled exceptions.",
			Severity:    severity.SeverityLow,
			Category:    govex.CategoryDAST,
		},
	}

	r := vulnreport.NewReport("Q3 Vulnerability Report", set)
	r.Subtitle = "Example App Security Assessment"
	r.Organization = "Example Corp"
	r.Author = "Security Team"
	r.Classification = "Confidential"
	r.GeneratedAt = &gen
	r.Summary = "Three findings were identified during the quarterly assessment: " +
		"one High severity SQL injection, one Medium severity outdated dependency, " +
		"and one Low severity information disclosure.\n\n" +
		"Remediation of the High severity finding is scheduled within the 30-day SLA window."
	return r
}
