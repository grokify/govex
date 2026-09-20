package slaexception

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/invopop/jsonschema"
)

const SchemaVersion = "1.0"

// Exception represents an SLA exception notification for a security finding.
type Exception struct {
	SchemaVersion    string      `json:"schema_version" jsonschema:"description=Schema version for this document format,example=1.0"`
	Subject          string      `json:"subject" jsonschema:"description=Email subject line for the notification,example=SLA Exception – Low – Missing rate limiting"`
	Sender           Sender      `json:"sender" jsonschema:"description=Sender/signatory information for the notification"`
	CustomerName     string      `json:"customer_name" jsonschema:"description=Name of the customer receiving the notification,example=Widget Inc"`
	Application      string      `json:"application" jsonschema:"description=Name of the affected application,example=Payments API"`
	Finding          Finding     `json:"finding" jsonschema:"description=Details of the security finding"`
	CVSS             *CVSS       `json:"cvss,omitempty" jsonschema:"description=CVSS scoring details (optional)"`
	SLA              SLA         `json:"sla" jsonschema:"description=SLA timeline information"`
	DelayReasons     []string    `json:"delay_reasons" jsonschema:"description=List of reasons for the remediation delay,example=Dependent on upstream API gateway change"`
	RiskAssessment   string      `json:"risk_assessment" jsonschema:"description=Assessment of the risk posed by this finding,example=Low likelihood of exploitation due to internal-only access."`
	Mitigations      []string    `json:"mitigations" jsonschema:"description=List of mitigating controls in place,example=WAF rate limiting rules in place"`
	RemediationPlan  string      `json:"remediation_plan" jsonschema:"description=Plan for remediating the finding,example=Implement native rate limiting in service layer"`
	Milestones       []Milestone `json:"milestones,omitempty" jsonschema:"description=Phased remediation milestones with target dates"`
	Approver         *Approver   `json:"approver,omitempty" jsonschema:"description=Senior leader who approved this SLA exception"`
	EscalationPolicy []string    `json:"escalation_policy,omitempty" jsonschema:"description=Actions taken if threat landscape changes materially,example=Reassess severity and fast-track remediation"`
}

// Sender represents the sender/signatory of the SLA exception notification.
type Sender struct {
	Name    string `json:"name" jsonschema:"description=Full name of the sender,example=Jane Smith"`
	Title   string `json:"title" jsonschema:"description=Job title of the sender,example=Security Engineer"`
	Team    string `json:"team" jsonschema:"description=Team or department of the sender,example=Application Security"`
	Company string `json:"company" jsonschema:"description=Company name of the sender,example=Acme Corp"`
	Email   string `json:"email" jsonschema:"description=Email address of the sender,format=email,example=security@acme.com"`
	Phone   string `json:"phone,omitempty" jsonschema:"description=Phone number of the sender (optional),example=+1-555-123-4567"`
}

// Finding represents the security finding details.
type Finding struct {
	Title      string `json:"title" jsonschema:"description=Title of the security finding,example=Missing rate limiting"`
	Severity   string `json:"severity" jsonschema:"description=Severity level of the finding,enum=Low,enum=Moderate,enum=High,enum=Critical,example=Low"`
	Identifier string `json:"identifier" jsonschema:"description=Unique identifier for the finding,example=APPSEC-1234"`
	DetectedOn string `json:"detected_on" jsonschema:"description=Date the finding was detected (ISO 8601 format YYYY-MM-DD),format=date,example=2026-04-01"`
}

// CVSS represents Common Vulnerability Scoring System details.
type CVSS struct {
	Score   float64 `json:"score" jsonschema:"description=CVSS numeric score (0.0-10.0),minimum=0,maximum=10,example=3.1"`
	Version string  `json:"version" jsonschema:"description=CVSS version used for scoring,example=4.0"`
	Vector  string  `json:"vector" jsonschema:"description=CVSS vector string,example=AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"`
}

// SLA represents Service Level Agreement details for remediation.
type SLA struct {
	TargetDays      int    `json:"target_days" jsonschema:"description=Target number of days for remediation based on severity,example=90"`
	OriginalDueDate string `json:"original_due_date" jsonschema:"description=Original SLA due date (ISO 8601 format YYYY-MM-DD),format=date,example=2026-06-30"`
	NewDueDate      string `json:"new_due_date" jsonschema:"description=New expected remediation date (ISO 8601 format YYYY-MM-DD),format=date,example=2026-07-31"`
}

// Milestone represents a phased remediation checkpoint.
type Milestone struct {
	Phase          int    `json:"phase" jsonschema:"description=Phase number,example=1"`
	Description    string `json:"description" jsonschema:"description=What this phase delivers,example=Deploy CSP in report-only mode"`
	TargetDate     string `json:"target_date" jsonschema:"description=Target completion date (ISO 8601 format YYYY-MM-DD),format=date,example=2026-08-01"`
	CustomerImpact string `json:"customer_impact" jsonschema:"description=Expected impact to customers,example=None — monitoring only"`
}

// Approver represents the senior leader who approved the SLA exception.
type Approver struct {
	Name         string `json:"name" jsonschema:"description=Full name of the approver,example=John Doe"`
	Title        string `json:"title" jsonschema:"description=Job title of the approver,example=VP of Engineering"`
	ApprovalDate string `json:"approval_date" jsonschema:"description=Date of approval (ISO 8601 format YYYY-MM-DD),format=date,example=2026-04-10"`
}

// NewException creates a new Exception with the schema version set.
func NewException() *Exception {
	return &Exception{
		SchemaVersion: SchemaVersion,
	}
}

// GenerateSubject generates a subject line from severity and finding title.
func GenerateSubject(severity, findingTitle string) string {
	return fmt.Sprintf("SLA Exception – %s – %s", severity, findingTitle)
}

// SetSubjectFromFinding sets the subject line based on the finding details.
func (e *Exception) SetSubjectFromFinding() {
	e.Subject = GenerateSubject(e.Finding.Severity, e.Finding.Title)
}

// HasCVSS returns true if CVSS information is available.
func (e *Exception) HasCVSS() bool {
	return e.CVSS != nil
}

// IsHighOrCritical returns true if the finding severity is High or Critical.
func (e *Exception) IsHighOrCritical() bool {
	return e.Finding.Severity == "High" || e.Finding.Severity == "Critical"
}

// HasMilestones returns true if milestones are defined.
func (e *Exception) HasMilestones() bool {
	return len(e.Milestones) > 0
}

// HasApprover returns true if an approver is defined.
func (e *Exception) HasApprover() bool {
	return e.Approver != nil
}

// HasEscalationPolicy returns true if escalation policy is defined.
func (e *Exception) HasEscalationPolicy() bool {
	return len(e.EscalationPolicy) > 0
}

// FormatDate converts an ISO 8601 date string to a human-readable format.
// Input: "2026-06-30" Output: "June 30, 2026"
func FormatDate(isoDate string) (string, error) {
	t, err := time.Parse(time.DateOnly, isoDate)
	if err != nil {
		return "", fmt.Errorf("invalid date format: %w", err)
	}
	return t.Format("January 2, 2006"), nil
}

// FormatDateOrEmpty returns formatted date or empty string on error.
func FormatDateOrEmpty(isoDate string) string {
	formatted, err := FormatDate(isoDate)
	if err != nil {
		return ""
	}
	return formatted
}

// FormatDateMonthYear converts an ISO 8601 date string to month and year format.
// Input: "2026-08-01" Output: "August 2026"
func FormatDateMonthYear(isoDate string) string {
	t, err := time.Parse(time.DateOnly, isoDate)
	if err != nil {
		return ""
	}
	return t.Format("January 2006")
}

// ReadFile reads an Exception from a JSON file.
func ReadFile(filename string) (*Exception, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	var e Exception
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	return &e, nil
}

// WriteFile writes an Exception to a JSON file.
func (e *Exception) WriteFile(filename string) error {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}

// JSON returns the Exception as a JSON string.
func (e *Exception) JSON() (string, error) {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// JSONSchema returns the JSON Schema for the Exception type.
func JSONSchema() ([]byte, error) {
	reflector := &jsonschema.Reflector{
		DoNotReference: true,
	}
	schema := reflector.Reflect(&Exception{})
	schema.Title = "SLA Exception Notification"
	schema.Description = "Schema for SLA exception notification letters for security findings"
	schema.Version = "https://json-schema.org/draft/2020-12/schema"

	return json.MarshalIndent(schema, "", "  ")
}

// JSONSchemaString returns the JSON Schema as a string.
func JSONSchemaString() (string, error) {
	data, err := JSONSchema()
	if err != nil {
		return "", err
	}
	return string(data), nil
}
