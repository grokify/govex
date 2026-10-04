package poam

import (
	"strings"
	"time"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/govex"
	"github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/security"
)

// Finding wraps a findingspec.Finding so it can be rendered as a POA&M item.
// It is a generic, scanner-agnostic POA&M source: any adapter that produces the
// shared findingspec IR (not just AWS Inspector) can generate POA&M through it.
type Finding struct {
	findingspec.Finding
}

// detail decodes the security VulnerabilityDetail payload from the finding. Only
// security-domain findings carry it; for any other finding (or on decode error)
// an empty detail is returned and dependent fields fall back to "".
func (f Finding) detail() security.VulnerabilityDetail {
	detail, err := findingspec.DetailAs[security.VulnerabilityDetail](f.Finding)
	if err != nil {
		return security.VulnerabilityDetail{}
	}
	return detail
}

// cveID returns the CVE identifier for the finding: the first detail CVE with a
// "CVE-" prefix, else the finding RuleID when it is itself a CVE, else "".
func (f Finding) cveID(detail security.VulnerabilityDetail) string {
	for _, cve := range detail.CVEs {
		if strings.HasPrefix(cve, "CVE-") {
			return cve
		}
	}
	if strings.HasPrefix(f.RuleID, "CVE-") {
		return f.RuleID
	}
	return ""
}

// POAMItemOpen reports whether the finding still requires attention. Unset,
// open, and confirmed findings are open.
func (f Finding) POAMItemOpen() bool {
	return f.Status.Open()
}

// POAMItemClosed reports whether the finding has been closed.
func (f Finding) POAMItemClosed() bool {
	return !f.Status.Open()
}

// POAMItemValue resolves a single POA&M field for the finding.
func (f Finding) POAMItemValue(field POAMField, opts *govex.ValueOptions, overrides func(field POAMField) (*string, error)) (string, error) {
	dateFormat := time.DateOnly
	if opts != nil && opts.DateFormat != "" {
		dateFormat = opts.DateFormat
	}
	// Step 1: check overrides.
	if overrides != nil {
		if v, err := overrides(field); err != nil {
			return "", err
		} else if v != nil {
			return *v, nil
		}
	}
	detail := f.detail()
	// Step 2: map the field.
	switch field {
	case FieldWeaknessName:
		return f.Title, nil
	case FieldWeaknessDescription:
		return f.Description, nil
	case FieldWeaknessDetectorSource:
		return f.Source.Tool, nil
	case FieldWeaknessSourceIdentifier:
		return f.RuleID, nil
	case FieldControls:
		if f.Domain == findingspec.DomainSecurity {
			return "RA-5", nil
		}
		return "", nil
	case FieldCVE:
		return f.cveID(detail), nil
	case FieldAssetIdentifier:
		if detail.Artifact != nil && detail.Artifact.ImageDigest != "" {
			return detail.Artifact.ImageDigest, nil
		}
		if detail.Artifact != nil && detail.Artifact.Image != "" {
			return detail.Artifact.Image, nil
		}
		if f.Location != nil && f.Location.Repo != "" {
			return f.Location.Repo, nil
		}
		if f.Location != nil {
			return f.Location.Component, nil
		}
		return "", nil
	case FieldServiceName:
		if detail.Artifact != nil && detail.Artifact.Image != "" {
			return detail.Artifact.Image, nil
		}
		if f.Location != nil {
			return f.Location.Component, nil
		}
		return "", nil
	case FieldOriginalRiskRating:
		return f.Severity.Name(), nil
	case FieldAdjustedRiskRating:
		if detail.ResidualSeverity != "" {
			return detail.ResidualSeverity.Name(), nil
		}
		return "", nil
	case FieldOriginalDetectionDate:
		if start := f.slaStart(opts); start != nil {
			return start.Format(dateFormat), nil
		}
		return "", nil
	case FieldScheduledCompletionDate:
		if opts == nil || opts.SLAOptions == nil || opts.SLAOptions.SLAPolicy == nil {
			return "", nil
		}
		start := f.slaStart(opts)
		if start == nil {
			return "", nil
		}
		due, err := opts.SLAOptions.SLAPolicy.DueDate(f.Severity.Name(), *start)
		if err != nil {
			return "", err
		} else if due == nil {
			return "", nil
		}
		return due.Format(dateFormat), nil
	case FieldOverallRemediationPlan:
		return f.remediationPlan(detail, opts), nil
	case FieldBindingOperationalDirective2201Tracking:
		if opts == nil || opts.CISAKEVC == nil {
			return "", nil
		}
		cveID := f.cveID(detail)
		if cveID == "" {
			return "No", nil
		} else if kev := opts.CISAKEVC.CVE(cveID); kev == nil {
			return "No", nil
		}
		return "Yes", nil
	case FieldBindingOperationalDirective2201DueDate:
		if opts == nil || opts.CISAKEVC == nil {
			return "", nil
		}
		cveID := f.cveID(detail)
		if cveID == "" {
			return "", nil
		} else if kev := opts.CISAKEVC.CVE(cveID); kev == nil {
			return "", nil
		} else {
			return kev.DueDate, nil
		}
	case FieldVendorDependency:
		if detail.Fix == nil || detail.Fix.State != security.FixStateFixed {
			return "Yes", nil
		}
		return "No", nil
	case FieldFalsePositive:
		return "No", nil
	default:
		return "", nil
	}
}

// slaStart returns the SLA start date for the finding: the fixed SLA start date
// when set, else the finding's DetectedAt.
func (f Finding) slaStart(opts *govex.ValueOptions) *time.Time {
	if opts != nil && opts.SLAOptions != nil && opts.SLAOptions.SLAStartDateFixed != nil {
		return opts.SLAOptions.SLAStartDateFixed
	}
	return f.DetectedAt
}

// remediationPlan renders the overall remediation plan text. It returns "" when
// the inputs are incomplete (missing package, fix version, or SLA), swallowing
// the renderer's validation error.
func (f Finding) remediationPlan(detail security.VulnerabilityDetail, opts *govex.ValueOptions) string {
	info := POAMItemUpgradeRemedationInfo{
		VulnerabilityID: f.RuleID,
		Packages:        POAMItemUpgradeRemedationPackages{},
	}
	if opts != nil && opts.SLAOptions != nil && opts.SLAOptions.SLAPolicy != nil {
		info.SLADays = opts.SLAOptions.SLAPolicy.SeveritySLADays(f.Severity.Name())
	}
	if detail.Package != nil {
		var fixVersion string
		if detail.Fix != nil && len(detail.Fix.Versions) > 0 {
			fixVersion = detail.Fix.Versions[0]
		}
		info.Packages = append(info.Packages, POAMItemUpgradeRemedationPackage{
			Name:           detail.Package.Name,
			CurVersion:     detail.Package.Version,
			FixVersion:     fixVersion,
			PackageManager: detail.Package.Ecosystem,
		})
	}
	out, err := info.String()
	if err != nil {
		return ""
	}
	return out
}

// POAMItemValues resolves the given POA&M fields for the finding, in order.
func (f Finding) POAMItemValues(fields []POAMField, opts *govex.ValueOptions, overrides func(field POAMField) (*string, error)) ([]string, error) {
	var out []string
	for _, field := range fields {
		if v, err := f.POAMItemValue(field, opts, overrides); err != nil {
			return out, err
		} else {
			out = append(out, v)
		}
	}
	return out, nil
}

// FromFindings renders a POA&M table from a slice of findingspec findings. Any
// scanner adapter that emits the shared findingspec IR can use it.
func FromFindings(findings []findingspec.Finding, opts *govex.ValueOptions, overrides func(field POAMField) (*string, error)) (*table.Table, error) {
	items := make([]POAMItem, 0, len(findings))
	for _, f := range findings {
		items = append(items, Finding{f})
	}
	return Table(items, opts, overrides)
}
