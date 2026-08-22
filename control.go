package govex

import (
	"time"
)

// Control functions.
const (
	ControlFunctionPreventive = "preventive"
	ControlFunctionDetective  = "detective"
	ControlFunctionCorrective = "corrective"
)

// Risk dimensions a control can reduce.
const (
	ReducesLikelihood = "likelihood"
	ReducesImpact     = "impact"
)

// Control effectiveness levels.
const (
	EffectivenessHigh   = "high"
	EffectivenessMedium = "medium"
	EffectivenessLow    = "low"
)

// CompensatingControl is a measure that reduces the exploitability or impact
// of a vulnerability without remediating it. Controls that justify CVSS
// environmental metric changes list them in ModifiedMetrics, making a
// residual severity vector derivable from its controls rather than asserted
// independently. Detective controls (monitoring, WAF rules) typically modify
// no metric and instead support the qualitative residual risk rationale.
type CompensatingControl struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Description     string     `json:"description,omitempty"`
	Function        string     `json:"function,omitempty"`        // preventive, detective, corrective
	Reduces         []string   `json:"reduces,omitempty"`         // likelihood, impact
	ModifiedMetrics []string   `json:"modifiedMetrics,omitempty"` // CVSS environmental metrics this control justifies, e.g. "MAV:A"
	Effectiveness   string     `json:"effectiveness,omitempty"`   // high, medium, low
	Verified        bool       `json:"verified,omitempty"`
	VerifiedMethod  string     `json:"verifiedMethod,omitempty"`
	LastVerifiedAt  *time.Time `json:"lastVerifiedAt,omitempty"`
	Owner           string     `json:"owner,omitempty"`
}

// Exception statuses.
const (
	ExceptionStatusRequested = "requested"
	ExceptionStatusApproved  = "approved"
	ExceptionStatusRejected  = "rejected"
	ExceptionStatusExpired   = "expired"
)

// ExceptionStatus records the approval state of a risk exception for a
// vulnerability. SLA policy: the SLA clock runs on inherent severity until
// an exception is approved, after which it runs on residual severity.
type ExceptionStatus struct {
	Status     string     `json:"status,omitempty"` // requested, approved, rejected, expired
	ApprovedAt *time.Time `json:"approvedAt,omitempty"`
	ApprovedBy string     `json:"approvedBy,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	Reference  string     `json:"reference,omitempty"`
	URL        string     `json:"url,omitempty"`
}

// IsApprovedAt reports whether the exception is approved and unexpired as of
// the provided time. A nil receiver reports false.
func (ex *ExceptionStatus) IsApprovedAt(t time.Time) bool {
	if ex == nil || ex.Status != ExceptionStatusApproved {
		return false
	}
	if ex.ApprovedAt != nil && t.Before(*ex.ApprovedAt) {
		return false
	}
	if ex.ExpiresAt != nil && t.After(*ex.ExpiresAt) {
		return false
	}
	return true
}
