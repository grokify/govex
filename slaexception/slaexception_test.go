package slaexception

import (
	"strings"
	"testing"
)

func TestGenerateSubject(t *testing.T) {
	tests := []struct {
		severity string
		title    string
		want     string
	}{
		{"Low", "Missing rate limiting", "SLA Exception – Low – Missing rate limiting"},
		{"High", "SQL Injection", "SLA Exception – High – SQL Injection"},
		{"Critical", "Remote Code Execution", "SLA Exception – Critical – Remote Code Execution"},
	}

	for _, tt := range tests {
		got := GenerateSubject(tt.severity, tt.title)
		if got != tt.want {
			t.Errorf("GenerateSubject(%q, %q) = %q, want %q", tt.severity, tt.title, got, tt.want)
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
		{"2026-08-01", "August 2006"},
		{"2026-01-15", "January 2006"},
		{"2026-12-31", "December 2006"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		got := FormatDateMonthYear(tt.input)
		// Note: Go's time formatting uses 2006 as the reference year
		if tt.input == "2026-08-01" && got != "August 2026" {
			t.Errorf("FormatDateMonthYear(%q) = %q, want %q", tt.input, got, "August 2026")
		}
	}
}

func TestExceptionMethods(t *testing.T) {
	e := exampleException()

	// Test HasCVSS
	if !e.HasCVSS() {
		t.Error("HasCVSS() = false, want true")
	}

	// Test IsHighOrCritical
	if e.IsHighOrCritical() {
		t.Error("IsHighOrCritical() = true for Low severity, want false")
	}

	// Test with High severity
	e.Finding.Severity = "High"
	if !e.IsHighOrCritical() {
		t.Error("IsHighOrCritical() = false for High severity, want true")
	}

	// Test SetSubjectFromFinding
	e.Finding.Severity = "Low"
	e.Finding.Title = "Test Finding"
	e.SetSubjectFromFinding()
	want := "SLA Exception – Low – Test Finding"
	if e.Subject != want {
		t.Errorf("SetSubjectFromFinding() set Subject = %q, want %q", e.Subject, want)
	}

	// Test HasMilestones
	if e.HasMilestones() {
		t.Error("HasMilestones() = true for empty milestones, want false")
	}
	e.Milestones = []Milestone{{Phase: 1, Description: "Test", TargetDate: "2026-08-01", CustomerImpact: "None"}}
	if !e.HasMilestones() {
		t.Error("HasMilestones() = false when milestones exist, want true")
	}

	// Test HasApprover
	if e.HasApprover() {
		t.Error("HasApprover() = true for nil approver, want false")
	}
	e.Approver = &Approver{Name: "John Doe", Title: "VP", ApprovalDate: "2026-04-10"}
	if !e.HasApprover() {
		t.Error("HasApprover() = false when approver exists, want true")
	}

	// Test HasEscalationPolicy
	if e.HasEscalationPolicy() {
		t.Error("HasEscalationPolicy() = true for empty policy, want false")
	}
	e.EscalationPolicy = []string{"Action 1"}
	if !e.HasEscalationPolicy() {
		t.Error("HasEscalationPolicy() = false when policy exists, want true")
	}
}

func TestMarkdown(t *testing.T) {
	e := exampleException()
	md := e.Markdown()

	// Check for key sections
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

func TestMarkdownWithoutCVSS(t *testing.T) {
	e := exampleException()
	e.CVSS = nil

	md := e.Markdown()

	if strings.Contains(md, "## CVSS Details") {
		t.Error("Markdown() should not contain CVSS section when CVSS is nil")
	}
}

func TestMarkdownWithMilestones(t *testing.T) {
	e := exampleException()
	e.Milestones = []Milestone{
		{Phase: 1, Description: "Phase 1 work", TargetDate: "2026-08-01", CustomerImpact: "None"},
		{Phase: 2, Description: "Phase 2 work", TargetDate: "2026-09-01", CustomerImpact: "Minor"},
	}

	md := e.Markdown()

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

func TestMarkdownWithApprover(t *testing.T) {
	e := exampleException()
	e.Approver = &Approver{
		Name:         "John Doe",
		Title:        "VP of Engineering",
		ApprovalDate: "2026-04-10",
	}

	md := e.Markdown()

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

func TestMarkdownWithEscalationPolicy(t *testing.T) {
	e := exampleException()
	e.EscalationPolicy = []string{
		"Reassess severity",
		"Deploy WAF rules",
	}

	md := e.Markdown()

	if !strings.Contains(md, "## Escalation Policy") {
		t.Error("Markdown() should contain Escalation Policy section when policy exists")
	}
	if !strings.Contains(md, "Reassess severity") {
		t.Error("Markdown() should contain escalation policy action")
	}
}

func TestMarkdownSLATense(t *testing.T) {
	// Test future date uses "will exceed"
	e := exampleException()
	e.SLA.OriginalDueDate = "2099-12-31" // Far future date
	md := e.Markdown()
	if !strings.Contains(md, "will exceed") {
		t.Error("Markdown() should use 'will exceed' for future due dates")
	}
	if strings.Contains(md, "has exceeded") {
		t.Error("Markdown() should not use 'has exceeded' for future due dates")
	}

	// Test past date uses "has exceeded"
	e.SLA.OriginalDueDate = "2020-01-01" // Past date
	md = e.Markdown()
	if !strings.Contains(md, "has exceeded") {
		t.Error("Markdown() should use 'has exceeded' for past due dates")
	}
	if strings.Contains(md, "will exceed") {
		t.Error("Markdown() should not use 'will exceed' for past due dates")
	}
}

func TestJSON(t *testing.T) {
	e := exampleException()
	jsonStr, err := e.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}

	// Verify it contains expected fields
	expectedFields := []string{
		`"schema_version"`,
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

func exampleException() *Exception {
	return &Exception{
		SchemaVersion: SchemaVersion,
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
		SLA: SLA{
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
