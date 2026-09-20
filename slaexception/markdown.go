package slaexception

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Markdown generates Pandoc Markdown from the Exception.
// Dates are formatted as human-readable (e.g., "June 30, 2026").
func (e *Exception) Markdown() string {
	var b strings.Builder

	// Title
	b.WriteString("# SLA Exception Notification\n\n")

	// Recipient and application
	fmt.Fprintf(&b, "**Dear %s,**\n\n", e.CustomerName)
	fmt.Fprintf(&b, "We are writing to inform you of a delay in remediation for a recently identified security finding affecting **%s**.\n\n", e.Application)

	// Finding Summary
	b.WriteString("## Finding Summary\n\n")
	fmt.Fprintf(&b, "- **Title:** %s\n", e.Finding.Title)
	fmt.Fprintf(&b, "- **Severity:** %s\n", e.Finding.Severity)
	fmt.Fprintf(&b, "- **Identifier:** %s\n", e.Finding.Identifier)
	fmt.Fprintf(&b, "- **Detected On:** %s\n", FormatDateOrEmpty(e.Finding.DetectedOn))
	fmt.Fprintf(&b, "- **Affected Component:** %s\n", e.Application)
	b.WriteString("\n")

	// CVSS (optional)
	if e.HasCVSS() {
		b.WriteString("## CVSS Details\n\n")
		fmt.Fprintf(&b, "- **Score:** %.1f (v%s)\n", e.CVSS.Score, e.CVSS.Version)
		fmt.Fprintf(&b, "- **Vector:** `%s`\n", e.CVSS.Vector)
		b.WriteString("\n")
	}

	// SLA Status
	b.WriteString("## SLA Status\n\n")
	fmt.Fprintf(&b, "Per our standard remediation policy, %s severity findings are targeted for resolution within %d days.\n\n", e.Finding.Severity, e.SLA.TargetDays)
	originalDue, err := time.Parse(time.DateOnly, e.SLA.OriginalDueDate)
	if err == nil && time.Now().After(originalDue) {
		fmt.Fprintf(&b, "At this time, remediation has exceeded the defined SLA deadline of **%s**.\n\n", FormatDateOrEmpty(e.SLA.OriginalDueDate))
	} else {
		fmt.Fprintf(&b, "At this time, we anticipate that remediation will exceed the defined SLA deadline of **%s**.\n\n", FormatDateOrEmpty(e.SLA.OriginalDueDate))
	}

	// Reason for Delay
	b.WriteString("## Reason for Delay\n\n")
	b.WriteString("The delay is due to the following factors:\n\n")
	for _, reason := range e.DelayReasons {
		fmt.Fprintf(&b, "- %s\n", reason)
	}
	b.WriteString("\n")

	// Risk Assessment
	b.WriteString("## Risk Assessment\n\n")
	b.WriteString("Based on our evaluation, this finding presents low risk to the confidentiality, integrity, and availability of the system:\n\n")
	b.WriteString(e.RiskAssessment)
	b.WriteString("\n\n")

	// Mitigating Controls
	b.WriteString("## Mitigating Controls\n\n")
	b.WriteString("The following controls reduce the risk during the extended remediation window:\n\n")
	for _, mitigation := range e.Mitigations {
		fmt.Fprintf(&b, "- %s\n", mitigation)
	}
	b.WriteString("\n")

	// Remediation Plan
	b.WriteString("## Remediation Plan\n\n")
	b.WriteString("We are actively tracking this issue and plan to remediate it by:\n\n")
	fmt.Fprintf(&b, "- **Planned Remediation Date:** %s\n", FormatDateOrEmpty(e.SLA.NewDueDate))
	fmt.Fprintf(&b, "- **Remediation Approach:** %s\n", e.RemediationPlan)
	b.WriteString("\n")

	// Remediation Milestones (optional)
	if e.HasMilestones() {
		b.WriteString("## Remediation Milestones\n\n")
		b.WriteString("| Phase | Milestone | Target Date | Impact to Customers |\n")
		b.WriteString("|-------|-----------|-------------|---------------------|\n")
		for _, m := range e.Milestones {
			fmt.Fprintf(&b, "| %d | %s | %s | %s |\n",
				m.Phase, m.Description, FormatDateMonthYear(m.TargetDate), m.CustomerImpact)
		}
		b.WriteString("\n")
	}

	// Ongoing Monitoring
	b.WriteString("## Ongoing Monitoring\n\n")
	b.WriteString("We will continue to:\n\n")
	b.WriteString("- Monitor for any changes in exploitability or threat landscape\n")
	b.WriteString("- Reassess priority if risk conditions change\n")
	b.WriteString("- Provide updates as progress is made\n")
	b.WriteString("\n")

	// Escalation Policy (optional)
	if e.HasEscalationPolicy() {
		b.WriteString("## Escalation Policy\n\n")
		b.WriteString("If the threat landscape changes materially, our security team will:\n\n")
		for _, action := range e.EscalationPolicy {
			fmt.Fprintf(&b, "- %s\n", action)
		}
		b.WriteString("\n")
	}

	// Exception Approval (optional)
	if e.HasApprover() {
		b.WriteString("## Exception Approval\n\n")
		b.WriteString("This SLA exception has been reviewed and approved by:\n\n")
		fmt.Fprintf(&b, "- **%s**, %s\n", e.Approver.Name, e.Approver.Title)
		fmt.Fprintf(&b, "- **Approval Date:** %s\n", FormatDateOrEmpty(e.Approver.ApprovalDate))
		b.WriteString("\n")
	}

	// Closing
	b.WriteString("---\n\n")
	b.WriteString("We appreciate your understanding as we balance remediation efforts with system stability and overall risk management. Please let us know if you would like additional details or a deeper technical review of this finding.\n\n")

	// Signature
	b.WriteString("Sincerely,\n\n")
	fmt.Fprintf(&b, "**%s**  \n", e.Sender.Name)
	fmt.Fprintf(&b, "%s, %s  \n", e.Sender.Title, e.Sender.Team)
	fmt.Fprintf(&b, "%s  \n", e.Sender.Company)
	b.WriteString(e.Sender.Email)
	if e.Sender.Phone != "" {
		fmt.Fprintf(&b, "  \n%s", e.Sender.Phone)
	}
	b.WriteString("\n")

	return b.String()
}

// WriteMarkdownFile writes the Markdown output to a file.
func (e *Exception) WriteMarkdownFile(filename string) error {
	content := e.Markdown()
	if err := os.WriteFile(filename, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write markdown file: %w", err)
	}
	return nil
}
