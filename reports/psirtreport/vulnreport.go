package psirtreport

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/grokify/mogo/log/slogutil"
	"github.com/grokify/mogo/pointer"
	"github.com/grokify/mogo/time/timeutil"

	"github.com/grokify/govex"
	"github.com/grokify/govex/severity"
)

const pdfMarkdownHeader = `---
header-includes:
 \usepackage{geometry}
 \geometry{margin=1cm}

documentclass: extarticle
fontsize: 10pt

output:
  pdf_document
---`

func Report(vs *govex.VulnerabilitiesSet, lgr *slog.Logger) (string, error) {
	if vs == nil {
		return "", errors.New("vulnerabilities set cannot be nil")
	}
	if lgr == nil {
		lgr = slogutil.Null()
	}

	colNameModule := "Module"
	colNameReporter := "Reporter"

	sb := strings.Builder{}
	if _, err := sb.WriteString(pdfMarkdownHeader + "\n\n"); err != nil {
		return "", err
	}

	// lineBreak := "\\"
	lineBreak := "<br/>\n\n"

	referenceTime := pointer.Dereference(vs.DateTime)

	{
		lgr.Info("vulnreport: writing summary")
		// Summary
		reportName := strings.TrimSpace(vs.Name)
		if reportName == "" {
			reportName = "Vulnerability Report"
		}

		if vs.DateTime == nil {
			return "", errors.New("vulnerability report date cannot be nil")
		}

		if _, err := sb.WriteString(fmt.Sprintf("# %s\n\nDate: %s\n\n", reportName,
			referenceTime.Format(timeutil.DateTextUS))); err != nil {
			return "", err
		}
	}

	{
		lgr.Info("vulnreport: writing overview")
		if _, err := sb.WriteString("## Overview\n\n"); err != nil {
			return "", err
		}
		if _, err := sb.WriteString("### Remediation SLA\n\n"); err != nil {
			return "", err
		}

		if vs.SLAPolicy != nil {
			txt := "The following SLA is used for this report. Findings are categorized as \"Within SLA\" if the SLA has not been breached. If the SLA has been breached, in the summary tables below, they are categorized by the number of days the SLA has been breached."
			sevToScoreMK := severity.SeverityToScoreTableMarkdown(true)
			slaTBL := vs.SLAPolicy.Table()
			if _, err := sb.WriteString(txt + "\n\n" + slaTBL.Markdown("\n", true) + "\n" +
				"### Severity Definitions\n\nSeverity is defined by CVSS 4.0 score for the vulnerability as confirmed by Saviynt AppSec team. The definition used by Saviynt AppSec is below. " +
				sevToScoreMK + "\n\n"); err != nil {
				return "", err
			}
		}
	}

	lgr.Info("vulnreport: writing summary tables")
	if _, err := sb.WriteString("## Summary Tables\n\n### All Findings\n\n"); err != nil {
		return "", err
	}
	{
		lgr.Info("vulnreport: writing summary tables: get stats by module")
		stats, err := vs.Vulnerabilities.SeverityStatsSetByModule(pointer.Dereference(
			vs.SLAPolicy), referenceTime, "__UNKNOWN_MODULE__")
		if err != nil {
			return "", err
		}

		lgr.Info("vulnreport: writing summary tables: get table")
		tbl := stats.Table(colNameModule)

		if _, err = sb.WriteString(tbl.Markdown("\n", false) + lineBreak); err != nil {
			return "", err
		}
	}

	sevs := []string{
		severity.SeverityCritical,
		severity.SeverityHigh,
		severity.SeverityMedium,
		severity.SeverityLow}

	lgr.Info("vulnreport: writing by severity")
	// 2. By Severity
	{
		for _, sev := range sevs {
			if _, err := sb.WriteString(
				fmt.Sprintf("### All %s Findings\n\n", sev)); err != nil {
				return "", err
			}
			vsSev := vs.FilterSeverity([]string{sev})
			if len(vsSev.Vulnerabilities) > 0 {
				stats, err := vsSev.Vulnerabilities.SeverityStatsSetByModule(pointer.Dereference(
					vs.SLAPolicy), time.Now(), "__UNKNOWN_MODULE__")
				if err != nil {
					return "", err
				}
				tbl := stats.Table(colNameModule)
				if _, err = sb.WriteString(tbl.Markdown("\n", false) + lineBreak); err != nil {
					return "", err
				}
			} else {
				if _, err := sb.WriteString("No findings.\n\n"); err != nil {
					return "", err
				}
			}
		}
	}

	lgr.Info("vulnreport: writing by reporter")
	if _, err := sb.WriteString("## By Reporter\n\n### All Findings\n\n"); err != nil {
		return "", err
	}
	{
		stats, err := vs.Vulnerabilities.SeverityStatsSetByReporter(pointer.Dereference(
			vs.SLAPolicy), time.Now(), "__UNKNOWN_MODULE__")
		if err != nil {
			return "", err
		}
		tbl := stats.Table(colNameReporter)
		if _, err = sb.WriteString(tbl.Markdown("\n", false) + lineBreak); err != nil {
			return "", err
		}

		{
			for _, sev := range sevs {
				if _, err := sb.WriteString(
					fmt.Sprintf("### All %s Findings by Reporter\n\n", sev)); err != nil {
					return "", err
				}
				vsSev := vs.FilterSeverity([]string{sev})
				if len(vsSev.Vulnerabilities) > 0 {
					stats, err := vsSev.Vulnerabilities.SeverityStatsSetByReporter(pointer.Dereference(
						vs.SLAPolicy), time.Now(), "__UNKNOWN_REPORTER__")
					if err != nil {
						return "", err
					}
					tbl := stats.Table(colNameReporter)
					if _, err = sb.WriteString(tbl.Markdown("\n", false) + lineBreak); err != nil {
						return "", err
					}
				} else {
					if _, err := sb.WriteString("No findings.\n\n"); err != nil {
						return "", err
					}
				}
			}
		}
	}

	lgr.Info("vulnreport: writing by module")
	{
		// 2. By Module
		if _, err := sb.WriteString("## Modules\n\n"); err != nil {
			return "", err
		}
		modules := vs.Vulnerabilities.Modules(true, true)
		for _, module := range modules {
			if _, err := sb.WriteString(
				fmt.Sprintf("### %s Module\n\n", module)); err != nil {
				return "", err
			}
			if _, err := sb.WriteString(
				fmt.Sprintf("#### %s Module Findings Overview\n\n", module)); err != nil {
				return "", err
			}
			vsMod := vs.FilterModule([]string{module})
			if len(vsMod.Vulnerabilities) > 0 {
				stats, err := vsMod.Vulnerabilities.SeverityStatsSetBySeverity(pointer.Dereference(
					vs.SLAPolicy), time.Now(), "__UNKNOWN_SEVERITY__")
				if err != nil {
					return "", err
				}
				tbl := stats.Table("Module")
				if _, err := sb.WriteString(tbl.Markdown("\n", false) + lineBreak); err != nil {
					return "", err
				}
			} else {
				if _, err := sb.WriteString("No findings.<br>"); err != nil {
					return "", err
				}
			}

			for _, sev := range sevs {
				if _, err := sb.WriteString(
					fmt.Sprintf("#### %s Module %s Severity Findings\n\n", module, sev)); err != nil {
					return "", err
				}
				vsModSev := vsMod.FilterSeverity([]string{sev})
				vsModSev.Vulnerabilities.SortBySLATimeStart()
				tbl, err := vsModSev.Vulnerabilities.TableFindingsOverdue(vs.VulnValueOpts, referenceTime)
				if err != nil {
					return "", err
				}
				if len(tbl.Rows) == 0 {
					if _, err = sb.WriteString("No findings.\n" + lineBreak); err != nil {
						return "", err
					}
				} else if _, err = sb.WriteString(tbl.Markdown("\n", true) + lineBreak); err != nil {
					return "", err
				}
			}
		}
	}

	return sb.String(), nil
}
