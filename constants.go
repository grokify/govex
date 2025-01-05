package govex

const (
	// Vulnerability source category.
	CategoryAntiVirus     = "Anti-Virus"
	CategoryCICD          = "CI/CD"
	CategoryCloudSecurity = "Cloud Security"
	CategoryContainer     = "Container"
	CategoryCSPM          = "CSPM"
	CategoryDAST          = "DAST"
	CategoryDevProcess    = "Dev Process"
	CategoryIaC           = "IaC"
	CategoryPentest       = "Pentest"
	CategoryRedTeam       = "Red Team"
	CategorySAST          = "SAST"
	CategorySCA           = "SCA"
	CategorySCI           = "Supply Chain Integrity"
	CategorySecrets       = "Secrets"
	CategorySecurityLogs  = "Security Logs"

	Priority1 = "Priority 1"
	Priority2 = "Priority 2"
	Priority3 = "Priority 3"

	P1DoNow   = "P1 - Do Now"
	P2DoNext  = "P2 - Do Next"
	P3DoLater = "P3 - Do Later"

	ReportName = "AppSec Scan Report"
)

func CategoriesSorted() []string {
	return []string{
		CategoryCICD,
		CategoryDevProcess,
		CategorySecrets,
		CategorySAST,
		CategorySCA,
		CategoryIaC,
		CategoryCSPM,
		CategoryContainer,
		CategorySCI,
		CategoryCloudSecurity,
		CategoryAntiVirus,
		CategorySecurityLogs,
		CategoryDAST,
		CategoryPentest,
		CategoryRedTeam,
	}
}
