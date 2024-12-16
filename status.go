package govex

const (
	// Status fields. See `docs/status.md` for more.
	StatusIdentified    = "Identified"
	StatusAnalyzing     = "Analyzing"
	StatusValidated     = "Validated"
	StatusMitigated     = "Mitigated"
	StatusInProgress    = "In Progress"
	StatusResolved      = "Resolved"
	StatusRemediated    = "Remediated"
	StatusClosed        = "Closed"
	StatusReopened      = "Reopened"
	StatusNotApplicable = "Not Applicable"
	StatusFalsePositive = "False Positive"
	StatusDeferred      = "Deferred"      // aka postponed
	StatusRiskAccepted  = "Risk Accepted" // aka ignored
)
