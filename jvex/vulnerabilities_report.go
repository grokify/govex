package jvex

import (
	"fmt"
	"strings"
	"time"

	"github.com/grokify/mogo/time/timeutil"
	"github.com/grokify/vex/cve20"
)

func (vs *Vulnerabilities) ReportMarkdownLinesFixedVersion(fixVersion string, releaseDate *time.Time) ([]string, error) {
	var lines []string

	severities := []string{
		cve20.BaseSeverityCritical,
		cve20.BaseSeverityHigh,
		cve20.BaseSeverityMedium,
		cve20.BaseSeverityLow}

	for _, sev := range severities {
		sevLines, err := vs.ReportMarkdownLinesVulnsFixed(fixVersion, releaseDate, sev)
		if err != nil {
			return lines, err
		}
		if len(sevLines) == 0 {
			continue
		}
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, sevLines...)
	}

	return lines, nil
}

func (vs *Vulnerabilities) ReportMarkdownLinesVulnsFixed(fixVersion string, releaseDate *time.Time, baseSeverity string) ([]string, error) {
	cves, err := vs.FilterFixedInVersion([]string{fixVersion}, baseSeverity)
	if err != nil {
		return []string{}, err
	}
	var lines []string
	for _, ci := range cves {
		if strings.TrimSpace(ci.Severity) != baseSeverity {
			continue
		}
		parts := []string{}

		dateStr := ""
		if ci.StartTime != nil {
			dateStr = ci.StartTime.Format(timeutil.DateTextUSAbbr3)
		}

		title := strings.TrimSpace(ci.Title)
		desc := strings.TrimSpace(ci.Description)

		if title != "" {
			title += " " + dateStr
		} else if desc != "" {
			desc += " " + dateStr
		}

		if title != "" {
			parts = append(parts, title)
		}
		if desc != "" {
			parts = append(parts, desc)
		}
		if len(parts) == 0 {
			continue
		}
		str := strings.Join(parts, ": ")
		if str == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("# %s", str))
	}
	return lines, nil
}
