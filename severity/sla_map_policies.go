package severity

// SLAMapFedRAMP represetns the SLA for FedRAMP.
// Ref: https://www.fedramp.gov/assets/resources/documents/CSP_POAM_Template_Completion_Guide.pdf
func SLAMapFedRAMP() SLAMap {
	return map[string]int64{
		SeverityCritical: 30,
		SeverityHigh:     30,
		SeverityMedium:   90,
		SeverityLow:      180,
	}
}

// SLAMapGitLab provides the SLA for GitLab.
// Ref: https://handbook.gitlab.com/handbook/security/product-security/vulnerability-management/sla/
func SLAMapGitLab() SLAMap {
	return map[string]int64{
		SeverityCritical: 30,
		SeverityHigh:     30,
		SeverityMedium:   90,
		SeverityLow:      180,
	}
}
