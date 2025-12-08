package spotbugs

import (
	"fmt"
	"strings"

	"github.com/grokify/mogo/pointer"
	"github.com/grokify/mogo/type/number"

	"github.com/grokify/govex"
	"github.com/grokify/govex/severity"
)

// ToGovex converts BugCollection to a slice of govex.Vulnerability
func (bc *BugCollection) ToGovexVulnerabilities(inclSecurityOnly bool) (govex.Vulnerabilities, error) {
	var vulns []govex.Vulnerability

	for _, file := range bc.Files {
		for _, bug := range file.BugInstances {
			cat := strings.ToUpper(strings.TrimSpace(bug.Category))
			if inclSecurityOnly {
				if cat != CategorySecurity {
					continue
				} else {
					cat = govex.CategorySAST
				}
			}

			sev, err := priorityToSeverity(bug.Priority)
			if err != nil {
				return nil, err
			}

			vuln := govex.Vulnerability{
				Category:         cat,
				Description:      strings.TrimSpace(bug.Message),
				Name:             strings.TrimSpace(bug.Type),
				Severity:         sev,
				SourceIdentifier: SourceSpotBugs,
				SourceComponent:  strings.TrimSpace(file.ClassName),
			}

			var lineStart *uint32
			if bug.LineNumber != 0 {
				if try, err := number.Itou32(bug.LineNumber); err != nil {
					return nil, err
				} else {
					lineStart = &try
				}
			}

			// Add location information if line number is available
			if bug.LineNumber > 0 {
				vuln.Location = &govex.Location{
					Path:      pointer.Pointer(strings.TrimSpace(file.ClassName)),
					LineStart: lineStart,
				}
			}

			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

// priorityToSeverity converts SpotBugs priority to severity level
func priorityToSeverity(priority string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "critical":
		return severity.SeverityCritical, nil
	case "high":
		return severity.SeverityHigh, nil
	case "medium":
		return severity.SeverityMedium, nil
	case "normal":
		return severity.SeverityMedium, nil
	case "low":
		return severity.SeverityLow, nil
	case "1":
		return severity.SeverityHigh, nil
	case "2":
		return severity.SeverityMedium, nil
	case "3":
		return severity.SeverityLow, nil
	default:
		return "", fmt.Errorf("unknown spotbugs xml source priority (%s)", priority)
	}
}
