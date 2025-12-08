package semgrep

import (
	"github.com/grokify/mogo/pointer"
	"github.com/grokify/mogo/text/markdown"
	"github.com/grokify/mogo/type/number"

	"github.com/grokify/govex"

	"github.com/grokify/govex/cwe"
	"github.com/grokify/govex/severity"
)

// ToGovexVulnerabilities converts a Semgrep Output to a slice of govex.Vulnerability
func (o *Output) ToGovexVulnerabilities() (govex.Vulnerabilities, error) {
	if o == nil {
		return nil, nil
	}

	vulns := make([]govex.Vulnerability, 0, len(o.Results))
	for _, result := range o.Results {
		vuln := govex.Vulnerability{
			ID:          result.CheckID,
			Name:        result.CheckID,
			Description: result.Extra.Message,
			Severity: parseSemgrepSeverity(
				result.Extra.Metadata.Category, result.Extra.Severity),
			Category: result.Extra.Metadata.Category,
			Location: &govex.Location{
				Path: pointer.Pointer(result.Path),
			},
		}

		if tryStart, err := number.Itou32(result.Start.Line); err != nil {
			return nil, err
		} else {
			vuln.Location.LineStart = pointer.Pointer(tryStart)
		}
		if tryEnd, err := number.Itou32(result.End.Line); err != nil {
			return nil, err
		} else {
			vuln.Location.LineEnd = pointer.Pointer(tryEnd)
		}

		if vuln.Category == CategorySecurity {
			vuln.Category = govex.CategorySAST
		}

		if len(result.Extra.Metadata.CWE) > 0 {
			cwes, err := cwe.ParsesCWEsAsPrefix(result.Extra.Metadata.CWE)
			if err != nil {
				return nil, err
			} else {
				vuln.CWE = cwes
			}
		}

		// Add source rule URL if available
		if result.Extra.Metadata.SourceRuleURL != "" {
			vuln.ReferenceURL = result.Extra.Metadata.SourceRuleURL
		} else if result.Extra.Metadata.SourceRuleUrl != "" {
			vuln.ReferenceURL = result.Extra.Metadata.SourceRuleUrl
		}

		// Add references as markdown links
		if len(result.Extra.Metadata.References) > 0 {
			vuln.References = make(markdown.Links, 0, len(result.Extra.Metadata.References))
			for _, ref := range result.Extra.Metadata.References {
				vuln.References = append(vuln.References, markdown.Link{URL: ref})
			}
		}

		// Add CWE information as tags
		if len(result.Extra.Metadata.CWE) > 0 {
			vuln.Tags = append(vuln.Tags, result.Extra.Metadata.CWE...)
		}

		// Add OWASP information as tags
		if len(result.Extra.Metadata.OWASP) > 0 {
			vuln.Tags = append(vuln.Tags, result.Extra.Metadata.OWASP...)
		}

		// Add technology information as tags
		if len(result.Extra.Metadata.Technology) > 0 {
			vuln.Tags = append(vuln.Tags, result.Extra.Metadata.Technology...)
		}

		// Set source identifier to Semgrep
		vuln.ScannerName = SourceSemgrep
		vuln.SourceComponent = result.Extra.EngineKind

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

func parseSemgrepSeverity(category, sev string) string {
	if category == CategorySecurity {
		switch sev {
		case SeverityError:
			return severity.SeverityHigh
		case SeverityWarning:
			return severity.SeverityMedium
		case SeverityInfo:
			return severity.SeverityLow
		default:
			return sev
		}
	} else {
		return sev
	}
}
