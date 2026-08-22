package vulnreport

import (
	"os"
	"strings"
)

// Markdown renders the report as a Markdown document.
func (r *Report) Markdown() (string, error) {
	var b strings.Builder

	b.WriteString("# " + r.Title + "\n\n")
	if r.Subtitle != "" {
		b.WriteString(r.Subtitle + "\n\n")
	}
	if r.Classification != "" {
		b.WriteString("**" + r.Classification + "**\n\n")
	}

	if fields := r.metaFields(); len(fields) > 0 {
		for _, f := range fields {
			b.WriteString("- **" + f.Label + ":** " + f.Value + "\n")
		}
		b.WriteString("\n")
	}

	if r.Summary != "" {
		b.WriteString("## Executive Summary\n\n")
		b.WriteString(r.Summary + "\n\n")
	}

	b.WriteString("## Severity Summary\n\n")
	b.WriteString(r.SeverityTable().Markdown("\n", true) + "\n\n")

	findings, err := r.FindingsTable()
	if err != nil {
		return "", err
	}
	b.WriteString("## Findings\n\n")
	if len(findings.Rows) == 0 {
		b.WriteString("No findings.\n")
	} else {
		b.WriteString(findings.Markdown("\n", true) + "\n")
	}

	if details := r.findingDetails(); len(details) > 0 {
		b.WriteString("\n## Finding Details\n")
		for _, d := range details {
			b.WriteString("\n### " + d.Name + "\n\n")
			writeDetailItem(&b, "ID", d.ID)
			writeDetailItem(&b, "Severity", d.Severity)
			writeDetailItem(&b, "Inherent Risk", d.RiskInherent)
			writeDetailItem(&b, "Residual Severity", d.SeverityResidual)
			writeDetailItem(&b, "Residual Risk", d.RiskResidual)
			b.WriteString("\n")
			if d.Description != "" {
				b.WriteString(d.Description + "\n")
			}
			if len(d.Controls) > 0 {
				b.WriteString("\n#### Compensating Controls\n\n")
				for _, ctrl := range d.Controls {
					b.WriteString("- **" + ctrl.Name + "**")
					if ctrl.Description != "" {
						b.WriteString(": " + ctrl.Description)
					}
					if ctrl.Verified {
						b.WriteString(" *(verified)*")
					}
					b.WriteString("\n")
				}
			}
		}
	}

	return b.String(), nil
}

func writeDetailItem(b *strings.Builder, label, value string) {
	if value != "" {
		b.WriteString("- **" + label + ":** " + value + "\n")
	}
}

// WriteMarkdownFile writes the report as a Markdown file.
func (r *Report) WriteMarkdownFile(filename string, perm os.FileMode) error {
	md, err := r.Markdown()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, []byte(md), perm)
}
