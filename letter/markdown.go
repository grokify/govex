package letter

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Markdown generates Pandoc Markdown from the Letter.
// The template is selected based on the letter Type.
func (l *Letter) Markdown() string {
	if l.IsHardening() {
		return l.markdownHardening()
	}
	return l.markdownSLA()
}

// markdownSLA generates Markdown for SLA exception letters.
func (l *Letter) markdownSLA() string {
	var b strings.Builder

	// Title
	b.WriteString("# SLA Exception Notification\n\n")

	// Recipient and application
	fmt.Fprintf(&b, "**Dear %s,**\n\n", l.CustomerName)
	fmt.Fprintf(&b, "We are writing to inform you of a delay in remediation for a recently identified security finding affecting **%s**.\n\n", l.Application)

	// Finding Summary
	b.WriteString("## Finding Summary\n\n")
	fmt.Fprintf(&b, "- **Title:** %s\n", l.Finding.Title)
	fmt.Fprintf(&b, "- **Severity:** %s\n", l.Finding.Severity)
	fmt.Fprintf(&b, "- **Identifier:** %s\n", l.Finding.Identifier)
	fmt.Fprintf(&b, "- **Detected On:** %s\n", FormatDateOrEmpty(l.Finding.DetectedOn))
	fmt.Fprintf(&b, "- **Affected Component:** %s\n", l.Application)
	b.WriteString("\n")

	// CVSS (optional)
	if l.HasCVSS() {
		b.WriteString("## CVSS Details\n\n")
		fmt.Fprintf(&b, "- **Score:** %.1f (v%s)\n", l.CVSS.Score, l.CVSS.Version)
		fmt.Fprintf(&b, "- **Vector:** `%s`\n", l.CVSS.Vector)
		b.WriteString("\n")
	}

	// SLA Status
	b.WriteString("## SLA Status\n\n")
	if l.SLA != nil {
		fmt.Fprintf(&b, "Per our standard remediation policy, %s severity findings are targeted for resolution within %d days.\n\n", l.Finding.Severity, l.SLA.TargetDays)
		originalDue, err := time.Parse(time.DateOnly, l.SLA.OriginalDueDate)
		if err == nil && time.Now().After(originalDue) {
			fmt.Fprintf(&b, "At this time, remediation has exceeded the defined SLA deadline of **%s**.\n\n", FormatDateOrEmpty(l.SLA.OriginalDueDate))
		} else {
			fmt.Fprintf(&b, "At this time, we anticipate that remediation will exceed the defined SLA deadline of **%s**.\n\n", FormatDateOrEmpty(l.SLA.OriginalDueDate))
		}
	}

	// Reason for Delay
	b.WriteString("## Reason for Delay\n\n")
	b.WriteString("The delay is due to the following factors:\n\n")
	for _, reason := range l.DelayReasons {
		fmt.Fprintf(&b, "- %s\n", reason)
	}
	b.WriteString("\n")

	// Risk Assessment
	b.WriteString("## Risk Assessment\n\n")
	b.WriteString("Based on our evaluation, this finding presents low risk to the confidentiality, integrity, and availability of the system:\n\n")
	b.WriteString(l.RiskAssessment)
	b.WriteString("\n\n")

	// Mitigating Controls
	b.WriteString("## Mitigating Controls\n\n")
	b.WriteString("The following controls reduce the risk during the extended remediation window:\n\n")
	for _, mitigation := range l.Mitigations {
		fmt.Fprintf(&b, "- %s\n", mitigation)
	}
	b.WriteString("\n")

	// Remediation Plan
	b.WriteString("## Remediation Plan\n\n")
	b.WriteString("We are actively tracking this issue and plan to remediate it by:\n\n")
	if l.SLA != nil {
		fmt.Fprintf(&b, "- **Planned Remediation Date:** %s\n", FormatDateOrEmpty(l.SLA.NewDueDate))
	}
	fmt.Fprintf(&b, "- **Remediation Approach:** %s\n", l.RemediationPlan)
	b.WriteString("\n")

	// Shared sections
	l.writeSharedSections(&b)

	return b.String()
}

// markdownHardening generates Markdown for security hardening notices.
func (l *Letter) markdownHardening() string {
	var b strings.Builder

	// Title
	b.WriteString("# Security Hardening Notice\n\n")

	// Recipient and application
	fmt.Fprintf(&b, "**Dear %s,**\n\n", l.CustomerName)
	fmt.Fprintf(&b, "We are writing to inform you of a planned security improvement affecting **%s**.\n\n", l.Application)

	// Finding Summary
	b.WriteString("## Finding Summary\n\n")
	fmt.Fprintf(&b, "- **Title:** %s\n", l.Finding.Title)
	fmt.Fprintf(&b, "- **Severity:** %s\n", l.Finding.Severity)
	fmt.Fprintf(&b, "- **Identifier:** %s\n", l.Finding.Identifier)
	fmt.Fprintf(&b, "- **Detected On:** %s\n", FormatDateOrEmpty(l.Finding.DetectedOn))
	fmt.Fprintf(&b, "- **Affected Component:** %s\n", l.Application)
	b.WriteString("\n")

	// CVSS (optional)
	if l.HasCVSS() {
		b.WriteString("## CVSS Details\n\n")
		fmt.Fprintf(&b, "- **Score:** %.1f (v%s)\n", l.CVSS.Score, l.CVSS.Version)
		fmt.Fprintf(&b, "- **Vector:** `%s`\n", l.CVSS.Vector)
		b.WriteString("\n")
	}

	// Rationale
	b.WriteString("## Rationale\n\n")
	b.WriteString(l.Rationale)
	b.WriteString("\n\n")

	// Risk Assessment
	b.WriteString("## Risk Assessment\n\n")
	b.WriteString("Based on our evaluation:\n\n")
	b.WriteString(l.RiskAssessment)
	b.WriteString("\n\n")

	// Mitigating Controls
	b.WriteString("## Current Mitigations\n\n")
	b.WriteString("The following controls are currently in place:\n\n")
	for _, mitigation := range l.Mitigations {
		fmt.Fprintf(&b, "- %s\n", mitigation)
	}
	b.WriteString("\n")

	// Remediation Plan
	b.WriteString("## Improvement Plan\n\n")
	b.WriteString("We plan to deliver this improvement by:\n\n")
	if l.TargetDate != "" {
		fmt.Fprintf(&b, "- **Target Completion Date:** %s\n", FormatDateOrEmpty(l.TargetDate))
	}
	fmt.Fprintf(&b, "- **Approach:** %s\n", l.RemediationPlan)
	b.WriteString("\n")

	// Shared sections
	l.writeSharedSections(&b)

	return b.String()
}

// writeSharedSections writes sections common to both letter types.
func (l *Letter) writeSharedSections(b *strings.Builder) {
	// Remediation Milestones (optional)
	if l.HasMilestones() {
		if l.IsHardening() {
			b.WriteString("## Implementation Milestones\n\n")
		} else {
			b.WriteString("## Remediation Milestones\n\n")
		}
		b.WriteString("| Phase | Milestone | Target Date | Impact to Customers |\n")
		b.WriteString("|-------|-----------|-------------|---------------------|\n")
		for _, m := range l.Milestones {
			fmt.Fprintf(b, "| %d | %s | %s | %s |\n",
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
	if l.HasEscalationPolicy() {
		b.WriteString("## Escalation Policy\n\n")
		b.WriteString("If the threat landscape changes materially, our security team will:\n\n")
		for _, action := range l.EscalationPolicy {
			fmt.Fprintf(b, "- %s\n", action)
		}
		b.WriteString("\n")
	}

	// Approval (optional)
	if l.HasApprover() {
		if l.IsHardening() {
			b.WriteString("## Approval\n\n")
			b.WriteString("This security improvement has been reviewed and approved by:\n\n")
		} else {
			b.WriteString("## Exception Approval\n\n")
			b.WriteString("This SLA exception has been reviewed and approved by:\n\n")
		}
		fmt.Fprintf(b, "- **%s**, %s\n", l.Approver.Name, l.Approver.Title)
		fmt.Fprintf(b, "- **Approval Date:** %s\n", FormatDateOrEmpty(l.Approver.ApprovalDate))
		b.WriteString("\n")
	}

	// Closing
	b.WriteString("---\n\n")
	if l.IsHardening() {
		b.WriteString("We appreciate your understanding as we continue to strengthen our security posture. Please let us know if you would like additional details or a deeper technical review of this improvement.\n\n")
	} else {
		b.WriteString("We appreciate your understanding as we balance remediation efforts with system stability and overall risk management. Please let us know if you would like additional details or a deeper technical review of this finding.\n\n")
	}

	// Signature
	b.WriteString("Sincerely,\n\n")
	fmt.Fprintf(b, "**%s**  \n", l.Sender.Name)
	fmt.Fprintf(b, "%s, %s  \n", l.Sender.Title, l.Sender.Team)
	fmt.Fprintf(b, "%s  \n", l.Sender.Company)
	b.WriteString(l.Sender.Email)
	if l.Sender.Phone != "" {
		fmt.Fprintf(b, "  \n%s", l.Sender.Phone)
	}
	b.WriteString("\n")
}

// WriteMarkdownFile writes the Markdown output to a file.
func (l *Letter) WriteMarkdownFile(filename string) error {
	content := l.Markdown()
	if err := os.WriteFile(filename, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write markdown file: %w", err)
	}
	return nil
}
