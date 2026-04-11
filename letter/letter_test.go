package letter

import (
	"strings"
	"testing"
)

func TestGenerateSubject(t *testing.T) {
	tests := []struct {
		letterType string
		severity   string
		title      string
		want       string
	}{
		{TypeSLA, "Low", "Missing rate limiting", "SLA Exception – Low – Missing rate limiting"},
		{TypeSLA, "High", "SQL Injection", "SLA Exception – High – SQL Injection"},
		{TypeHardening, "Low", "CSP Enhancement", "Security Hardening Notice – Low – CSP Enhancement"},
		{"", "Critical", "RCE", "SLA Exception – Critical – RCE"}, // default to SLA
	}

	for _, tt := range tests {
		got := GenerateSubject(tt.letterType, tt.severity, tt.title)
		if got != tt.want {
			t.Errorf("GenerateSubject(%q, %q, %q) = %q, want %q", tt.letterType, tt.severity, tt.title, got, tt.want)
		}
	}
}

func TestFormatDate(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"2026-06-30", "June 30, 2026", false},
		{"2026-01-01", "January 1, 2026", false},
		{"2026-12-25", "December 25, 2026", false},
		{"invalid", "", true},
		{"2026/06/30", "", true},
	}

	for _, tt := range tests {
		got, err := FormatDate(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("FormatDate(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("FormatDate(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatDateMonthYear(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"2026-08-01", "August 2026"},
		{"2026-01-15", "January 2026"},
		{"2026-12-31", "December 2026"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		got := FormatDateMonthYear(tt.input)
		if got != tt.want {
			t.Errorf("FormatDateMonthYear(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestLetterMethods(t *testing.T) {
	l := exampleSLALetter()

	// Test IsSLA
	if !l.IsSLA() {
		t.Error("IsSLA() = false, want true")
	}

	// Test IsHardening
	if l.IsHardening() {
		t.Error("IsHardening() = true for SLA type, want false")
	}

	// Test HasCVSS
	if !l.HasCVSS() {
		t.Error("HasCVSS() = false, want true")
	}

	// Test IsHighOrCritical
	if l.IsHighOrCritical() {
		t.Error("IsHighOrCritical() = true for Low severity, want false")
	}

	// Test with High severity
	l.Finding.Severity = "High"
	if !l.IsHighOrCritical() {
		t.Error("IsHighOrCritical() = false for High severity, want true")
	}

	// Test SetSubjectFromFinding
	l.Finding.Severity = "Low"
	l.Finding.Title = "Test Finding"
	l.SetSubjectFromFinding()
	want := "SLA Exception – Low – Test Finding"
	if l.Subject != want {
		t.Errorf("SetSubjectFromFinding() set Subject = %q, want %q", l.Subject, want)
	}

	// Test HasMilestones
	if l.HasMilestones() {
		t.Error("HasMilestones() = true for empty milestones, want false")
	}
	l.Milestones = []Milestone{{Phase: 1, Description: "Test", TargetDate: "2026-08-01", CustomerImpact: "None"}}
	if !l.HasMilestones() {
		t.Error("HasMilestones() = false when milestones exist, want true")
	}

	// Test HasApprover
	if l.HasApprover() {
		t.Error("HasApprover() = true for nil approver, want false")
	}
	l.Approver = &Approver{Name: "John Doe", Title: "VP", ApprovalDate: "2026-04-10"}
	if !l.HasApprover() {
		t.Error("HasApprover() = false when approver exists, want true")
	}

	// Test HasEscalationPolicy
	if l.HasEscalationPolicy() {
		t.Error("HasEscalationPolicy() = true for empty policy, want false")
	}
	l.EscalationPolicy = []string{"Action 1"}
	if !l.HasEscalationPolicy() {
		t.Error("HasEscalationPolicy() = false when policy exists, want true")
	}
}

func TestHardeningLetterMethods(t *testing.T) {
	l := exampleHardeningLetter()

	if l.IsSLA() {
		t.Error("IsSLA() = true for hardening type, want false")
	}

	if !l.IsHardening() {
		t.Error("IsHardening() = false, want true")
	}

	l.SetSubjectFromFinding()
	want := "Security Hardening Notice – Low – CSP Enhancement"
	if l.Subject != want {
		t.Errorf("SetSubjectFromFinding() set Subject = %q, want %q", l.Subject, want)
	}
}

func TestMarkdownSLA(t *testing.T) {
	l := exampleSLALetter()
	md := l.Markdown()

	// Check for SLA-specific sections
	requiredSections := []string{
		"# SLA Exception Notification",
		"## Finding Summary",
		"## SLA Status",
		"## Reason for Delay",
		"## Risk Assessment",
		"## Mitigating Controls",
		"## Remediation Plan",
		"## Ongoing Monitoring",
	}

	for _, section := range requiredSections {
		if !strings.Contains(md, section) {
			t.Errorf("Markdown() missing section: %q", section)
		}
	}

	// Check for SLA-specific content
	if !strings.Contains(md, "delay in remediation") {
		t.Error("SLA Markdown should contain 'delay in remediation'")
	}

	// Check for formatted dates
	if !strings.Contains(md, "June 30, 2026") {
		t.Error("Markdown() should contain formatted date 'June 30, 2026'")
	}

	// Check for CVSS section when present
	if !strings.Contains(md, "## CVSS Details") {
		t.Error("Markdown() should contain CVSS section when CVSS is present")
	}

	// Check sender info
	if !strings.Contains(md, "Jane Smith") {
		t.Error("Markdown() should contain sender name")
	}
}

func TestMarkdownHardening(t *testing.T) {
	l := exampleHardeningLetter()
	md := l.Markdown()

	// Check for hardening-specific sections
	requiredSections := []string{
		"# Security Hardening Notice",
		"## Finding Summary",
		"## Rationale",
		"## Risk Assessment",
		"## Current Mitigations",
		"## Improvement Plan",
		"## Ongoing Monitoring",
	}

	for _, section := range requiredSections {
		if !strings.Contains(md, section) {
			t.Errorf("Markdown() missing section: %q", section)
		}
	}

	// Check for hardening-specific content
	if !strings.Contains(md, "planned security improvement") {
		t.Error("Hardening Markdown should contain 'planned security improvement'")
	}

	// Should NOT contain SLA-specific sections
	if strings.Contains(md, "## SLA Status") {
		t.Error("Hardening Markdown should not contain '## SLA Status'")
	}
	if strings.Contains(md, "## Reason for Delay") {
		t.Error("Hardening Markdown should not contain '## Reason for Delay'")
	}
}

func TestMarkdownSLATense(t *testing.T) {
	// Test future date uses "will exceed"
	l := exampleSLALetter()
	l.SLA.OriginalDueDate = "2099-12-31" // Far future date
	md := l.Markdown()
	if !strings.Contains(md, "will exceed") {
		t.Error("Markdown() should use 'will exceed' for future due dates")
	}
	if strings.Contains(md, "has exceeded") {
		t.Error("Markdown() should not use 'has exceeded' for future due dates")
	}

	// Test past date uses "has exceeded"
	l.SLA.OriginalDueDate = "2020-01-01" // Past date
	md = l.Markdown()
	if !strings.Contains(md, "has exceeded") {
		t.Error("Markdown() should use 'has exceeded' for past due dates")
	}
	if strings.Contains(md, "will exceed") {
		t.Error("Markdown() should not use 'will exceed' for past due dates")
	}
}

func TestMarkdownWithMilestones(t *testing.T) {
	l := exampleSLALetter()
	l.Milestones = []Milestone{
		{Phase: 1, Description: "Phase 1 work", TargetDate: "2026-08-01", CustomerImpact: "None"},
		{Phase: 2, Description: "Phase 2 work", TargetDate: "2026-09-01", CustomerImpact: "Minor"},
	}

	md := l.Markdown()

	if !strings.Contains(md, "## Remediation Milestones") {
		t.Error("Markdown() should contain Remediation Milestones section when milestones exist")
	}
	if !strings.Contains(md, "| Phase | Milestone | Target Date | Impact to Customers |") {
		t.Error("Markdown() should contain milestones table header")
	}
	if !strings.Contains(md, "Phase 1 work") {
		t.Error("Markdown() should contain milestone description")
	}
}

func TestMarkdownHardeningWithMilestones(t *testing.T) {
	l := exampleHardeningLetter()
	l.Milestones = []Milestone{
		{Phase: 1, Description: "Phase 1 work", TargetDate: "2026-08-01", CustomerImpact: "None"},
	}

	md := l.Markdown()

	// Hardening uses "Implementation Milestones" instead of "Remediation Milestones"
	if !strings.Contains(md, "## Implementation Milestones") {
		t.Error("Hardening Markdown() should contain Implementation Milestones section")
	}
}

func TestMarkdownWithApprover(t *testing.T) {
	l := exampleSLALetter()
	l.Approver = &Approver{
		Name:         "John Doe",
		Title:        "VP of Engineering",
		ApprovalDate: "2026-04-10",
	}

	md := l.Markdown()

	if !strings.Contains(md, "## Exception Approval") {
		t.Error("Markdown() should contain Exception Approval section when approver exists")
	}
	if !strings.Contains(md, "John Doe") {
		t.Error("Markdown() should contain approver name")
	}
	if !strings.Contains(md, "VP of Engineering") {
		t.Error("Markdown() should contain approver title")
	}
}

func TestMarkdownHardeningWithApprover(t *testing.T) {
	l := exampleHardeningLetter()
	l.Approver = &Approver{
		Name:         "John Doe",
		Title:        "VP of Engineering",
		ApprovalDate: "2026-04-10",
	}

	md := l.Markdown()

	// Hardening uses "Approval" instead of "Exception Approval"
	if !strings.Contains(md, "## Approval") {
		t.Error("Hardening Markdown() should contain Approval section")
	}
	if strings.Contains(md, "## Exception Approval") {
		t.Error("Hardening Markdown() should not contain 'Exception Approval'")
	}
}

func TestMarkdownWithEscalationPolicy(t *testing.T) {
	l := exampleSLALetter()
	l.EscalationPolicy = []string{
		"Reassess severity",
		"Deploy WAF rules",
	}

	md := l.Markdown()

	if !strings.Contains(md, "## Escalation Policy") {
		t.Error("Markdown() should contain Escalation Policy section when policy exists")
	}
	if !strings.Contains(md, "Reassess severity") {
		t.Error("Markdown() should contain escalation policy action")
	}
}

func TestJSON(t *testing.T) {
	l := exampleSLALetter()
	jsonStr, err := l.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}

	// Verify it contains expected fields
	expectedFields := []string{
		`"schema_version"`,
		`"type"`,
		`"subject"`,
		`"sender"`,
		`"customer_name"`,
		`"finding"`,
		`"cvss"`,
		`"sla"`,
		`"delay_reasons"`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("JSON() missing field: %s", field)
		}
	}
}

func TestJSONHardening(t *testing.T) {
	l := exampleHardeningLetter()
	jsonStr, err := l.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}

	// Verify it contains hardening-specific fields
	if !strings.Contains(jsonStr, `"type": "hardening"`) {
		t.Error("JSON() should contain type: hardening")
	}
	if !strings.Contains(jsonStr, `"rationale"`) {
		t.Error("JSON() should contain rationale field")
	}
	// Should not contain SLA field
	if strings.Contains(jsonStr, `"sla"`) {
		t.Error("Hardening JSON() should not contain sla field")
	}
}

func TestNewLetter(t *testing.T) {
	// Default type
	l := NewLetter("")
	if l.Type != TypeSLA {
		t.Errorf("NewLetter(\"\") type = %q, want %q", l.Type, TypeSLA)
	}
	if l.SchemaVersion != SchemaVersion {
		t.Errorf("NewLetter() SchemaVersion = %q, want %q", l.SchemaVersion, SchemaVersion)
	}

	// Explicit type
	l = NewLetter(TypeHardening)
	if l.Type != TypeHardening {
		t.Errorf("NewLetter(TypeHardening) type = %q, want %q", l.Type, TypeHardening)
	}
}

func exampleSLALetter() *Letter {
	return &Letter{
		SchemaVersion: SchemaVersion,
		Type:          TypeSLA,
		Subject:       "SLA Exception – Low – Missing rate limiting",
		Sender: Sender{
			Name:    "Jane Smith",
			Title:   "Security Engineer",
			Team:    "Application Security",
			Company: "Acme Corp",
			Email:   "security@acme.com",
			Phone:   "+1-555-123-4567",
		},
		CustomerName: "Widget Inc",
		Application:  "Payments API",
		Finding: Finding{
			Title:      "Missing rate limiting",
			Severity:   "Low",
			Identifier: "APPSEC-1234",
			DetectedOn: "2026-04-01",
		},
		CVSS: &CVSS{
			Score:   3.1,
			Version: "4.0",
			Vector:  "AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		},
		SLA: &SLA{
			TargetDays:      90,
			OriginalDueDate: "2026-06-30",
			NewDueDate:      "2026-07-31",
		},
		DelayReasons: []string{
			"Dependent on upstream API gateway change",
		},
		RiskAssessment: "Low likelihood of exploitation due to internal-only access.",
		Mitigations: []string{
			"WAF rate limiting rules in place",
			"Monitoring enabled",
		},
		RemediationPlan: "Implement native rate limiting in service layer",
	}
}

func exampleHardeningLetter() *Letter {
	return &Letter{
		SchemaVersion: SchemaVersion,
		Type:          TypeHardening,
		Subject:       "Security Hardening Notice – Low – CSP Enhancement",
		Sender: Sender{
			Name:    "Jane Smith",
			Title:   "Security Engineer",
			Team:    "Application Security",
			Company: "Acme Corp",
			Email:   "security@acme.com",
			Phone:   "+1-555-123-4567",
		},
		CustomerName: "Widget Inc",
		Application:  "Customer Portal",
		Finding: Finding{
			Title:      "CSP Enhancement",
			Severity:   "Low",
			Identifier: "APPSEC-5678",
			DetectedOn: "2026-04-01",
		},
		CVSS: &CVSS{
			Score:   2.3,
			Version: "4.0",
			Vector:  "AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		},
		Rationale:      "Defense-in-depth improvement to strengthen CSP headers.",
		RiskAssessment: "Hardening opportunity, not an exploitable vulnerability.",
		Mitigations: []string{
			"Existing CSP headers provide baseline protection",
		},
		RemediationPlan: "Implement stricter CSP directives",
		TargetDate:      "2026-08-01",
	}
}
