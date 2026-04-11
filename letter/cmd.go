package letter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// CmdLetterCobra returns the letter cobra command for integration into govex CLI.
func CmdLetterCobra() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "letter",
		Short: "Generate security notification letters",
		Long: `letter generates security notification letters for security findings.

Supported letter types:
  - sla       SLA exception notification (default)
  - hardening Security hardening notice

It can read from a JSON file or accept parameters directly, and output
JSON IR and/or Pandoc Markdown for conversion to DOCX/PDF.`,
	}

	cmd.AddCommand(cmdGenerate())
	cmd.AddCommand(cmdSchema())
	cmd.AddCommand(cmdExample())

	return cmd
}

func cmdSchema() *cobra.Command {
	var outputFile string

	cmd := &cobra.Command{
		Use:   "schema",
		Short: "Output JSON Schema for the letter format",
		Long: `Output the JSON Schema that describes the letter JSON format.

This schema can be used by AI agents, validators, or documentation tools
to understand the expected structure of the input JSON.

Examples:
  # Print schema to stdout
  govex letter schema

  # Save schema to file
  govex letter schema --output schema.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			schema, err := JSONSchemaString()
			if err != nil {
				return fmt.Errorf("failed to generate schema: %w", err)
			}

			if outputFile != "" {
				if err := os.WriteFile(outputFile, []byte(schema), 0600); err != nil {
					return fmt.Errorf("failed to write schema file: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Wrote schema to: %s\n", outputFile)
			} else {
				fmt.Println(schema)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")

	return cmd
}

func cmdExample() *cobra.Command {
	var letterType string

	cmd := &cobra.Command{
		Use:   "example",
		Short: "Output an example JSON file",
		Long: `Output an example letter JSON file that can be used as a template.

Examples:
  # Print SLA exception example (default)
  govex letter example

  # Print hardening notice example
  govex letter example --type hardening

  # Save example to file
  govex letter example > finding.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var example *Letter

			if letterType == TypeHardening {
				example = exampleHardening()
			} else {
				example = exampleSLA()
			}

			data, err := json.MarshalIndent(example, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal example: %w", err)
			}

			fmt.Println(string(data))
			return nil
		},
	}

	cmd.Flags().StringVarP(&letterType, "type", "t", TypeSLA, "Letter type: 'sla' or 'hardening'")

	return cmd
}

func exampleSLA() *Letter {
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
		Milestones: []Milestone{
			{Phase: 1, Description: "Deploy rate limiting in report-only mode", TargetDate: "2026-08-01", CustomerImpact: "None — monitoring only"},
			{Phase: 2, Description: "Enable rate limiting enforcement", TargetDate: "2026-09-01", CustomerImpact: "None expected"},
		},
		Approver: &Approver{
			Name:         "John Doe",
			Title:        "VP of Engineering",
			ApprovalDate: "2026-04-10",
		},
		EscalationPolicy: []string{
			"Reassess severity and fast-track remediation as warranted",
			"Deploy additional WAF rules or virtual patches within 48 hours",
			"Notify affected customers of any change in risk posture",
		},
	}
}

func exampleHardening() *Letter {
	return &Letter{
		SchemaVersion: SchemaVersion,
		Type:          TypeHardening,
		Subject:       "Security Hardening Notice – Low – CSP Configuration Enhancement",
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
			Title:      "CSP Configuration Enhancement",
			Severity:   "Low",
			Identifier: "APPSEC-5678",
			DetectedOn: "2026-04-01",
		},
		CVSS: &CVSS{
			Score:   2.3,
			Version: "4.0",
			Vector:  "AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		},
		Rationale:      "This is a defense-in-depth improvement to strengthen our Content Security Policy. While not actively exploitable, enhancing our CSP headers provides additional protection against potential future threats and aligns with security best practices.",
		RiskAssessment: "This finding represents a hardening opportunity rather than an exploitable vulnerability. Current risk is minimal as no active exploit path exists.",
		Mitigations: []string{
			"Existing CSP headers provide baseline protection",
			"Web Application Firewall rules in place",
			"Regular security monitoring active",
		},
		RemediationPlan: "Implement stricter CSP directives with report-only rollout followed by enforcement",
		TargetDate:      "2026-08-01",
		Milestones: []Milestone{
			{Phase: 1, Description: "Deploy enhanced CSP in report-only mode", TargetDate: "2026-06-01", CustomerImpact: "None — monitoring only"},
			{Phase: 2, Description: "Analyze reports and adjust policy", TargetDate: "2026-07-01", CustomerImpact: "None"},
			{Phase: 3, Description: "Enable CSP enforcement", TargetDate: "2026-08-01", CustomerImpact: "None expected"},
		},
		Approver: &Approver{
			Name:         "John Doe",
			Title:        "VP of Engineering",
			ApprovalDate: "2026-04-10",
		},
		EscalationPolicy: []string{
			"Accelerate timeline if related vulnerabilities are discovered",
			"Notify stakeholders of any changes to the implementation plan",
		},
	}
}

func cmdGenerate() *cobra.Command {
	var (
		// Type
		letterType string
		// Input
		inputFile string
		// Output
		outputJSON   string
		outputMD     string
		outputStdout string
		// Customer/Application
		customerName string
		application  string
		// Finding
		findingTitle    string
		findingSeverity string
		findingID       string
		findingDate     string
		// CVSS
		cvssScore   float64
		cvssVersion string
		cvssVector  string
		// SLA (type=sla only)
		slaTargetDays   int
		slaOriginalDate string
		slaNewDate      string
		// Delay/Risk/Mitigation
		delayReasons   []string
		riskAssessment string
		mitigations    []string
		remediation    string
		// Hardening (type=hardening only)
		rationale  string
		targetDate string
		// Sender
		senderName    string
		senderTitle   string
		senderTeam    string
		senderCompany string
		senderEmail   string
		senderPhone   string
		// Milestones (optional)
		milestones []string
		// Approver (optional)
		approverName  string
		approverTitle string
		approverDate  string
		// Escalation Policy (optional)
		escalationPolicy []string
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate security notification letter",
		Long: `Generate a security notification letter from JSON input or command-line parameters.

Letter types:
  - sla       SLA exception notification (default)
  - hardening Security hardening notice

Examples:
  # Generate SLA exception from JSON file
  govex letter generate --input finding.json --output-md letter.md

  # Generate hardening notice from JSON file
  govex letter generate --type hardening --input notice.json --output-md letter.md

  # Generate SLA exception with parameters
  govex letter generate \
    --type sla \
    --customer "Widget Inc" \
    --application "Payments API" \
    --finding-title "Missing rate limiting" \
    --finding-severity Low \
    --finding-id APPSEC-1234 \
    --finding-date 2026-04-01 \
    --sla-target-days 90 \
    --sla-original-date 2026-06-30 \
    --sla-new-date 2026-07-31 \
    --delay-reason "Dependent on upstream API gateway change" \
    --risk "Low likelihood of exploitation due to internal-only access." \
    --mitigation "WAF rate limiting rules in place" \
    --remediation "Implement native rate limiting in service layer" \
    --sender-name "Jane Smith" \
    --sender-title "Security Engineer" \
    --sender-team "Application Security" \
    --sender-company "Acme Corp" \
    --sender-email "security@acme.com" \
    --output-md letter.md

  # Generate hardening notice with parameters
  govex letter generate \
    --type hardening \
    --customer "Widget Inc" \
    --application "Customer Portal" \
    --finding-title "CSP Configuration Enhancement" \
    --finding-severity Low \
    --finding-id APPSEC-5678 \
    --finding-date 2026-04-01 \
    --rationale "Defense-in-depth improvement to strengthen CSP." \
    --risk "Hardening opportunity, not an exploitable vulnerability." \
    --mitigation "Existing CSP headers provide baseline protection" \
    --remediation "Implement stricter CSP directives" \
    --target-date 2026-08-01 \
    --sender-name "Jane Smith" \
    --sender-title "Security Engineer" \
    --sender-team "Application Security" \
    --sender-company "Acme Corp" \
    --sender-email "security@acme.com" \
    --output-md letter.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var ltr *Letter
			var err error

			if inputFile != "" {
				ltr, err = ReadFile(inputFile)
				if err != nil {
					return fmt.Errorf("failed to read input file: %w", err)
				}
				// Override type from flag if provided and different from default
				if cmd.Flags().Changed("type") {
					ltr.Type = letterType
				}
			} else {
				ltr, err = buildLetterFromFlags(
					letterType,
					customerName, application,
					findingTitle, findingSeverity, findingID, findingDate,
					cvssScore, cvssVersion, cvssVector,
					slaTargetDays, slaOriginalDate, slaNewDate,
					delayReasons, riskAssessment, mitigations, remediation,
					rationale, targetDate,
					senderName, senderTitle, senderTeam, senderCompany, senderEmail, senderPhone,
					milestones, approverName, approverTitle, approverDate, escalationPolicy,
				)
				if err != nil {
					return fmt.Errorf("failed to build letter from flags: %w", err)
				}
			}

			if outputJSON == "" && outputMD == "" && outputStdout == "" {
				return fmt.Errorf("at least one output required: --output-json, --output-md, or --stdout")
			}

			if outputJSON != "" {
				if err := ltr.WriteFile(outputJSON); err != nil {
					return fmt.Errorf("failed to write JSON file: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Wrote JSON to: %s\n", outputJSON)
			}

			if outputMD != "" {
				if err := ltr.WriteMarkdownFile(outputMD); err != nil {
					return fmt.Errorf("failed to write Markdown file: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Wrote Markdown to: %s\n", outputMD)
			}

			if outputStdout != "" {
				switch strings.ToLower(outputStdout) {
				case "json":
					data, err := json.MarshalIndent(ltr, "", "  ")
					if err != nil {
						return fmt.Errorf("failed to marshal JSON: %w", err)
					}
					fmt.Println(string(data))
				case "md", "markdown":
					fmt.Println(ltr.Markdown())
				default:
					return fmt.Errorf("invalid --stdout value: %s (use 'json' or 'md')", outputStdout)
				}
			}

			return nil
		},
	}

	// Type
	cmd.Flags().StringVarP(&letterType, "type", "t", TypeSLA, "Letter type: 'sla' or 'hardening'")

	// Input
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input JSON file")

	// Output
	cmd.Flags().StringVar(&outputJSON, "output-json", "", "Output JSON file path")
	cmd.Flags().StringVar(&outputMD, "output-md", "", "Output Markdown file path")
	cmd.Flags().StringVar(&outputStdout, "stdout", "", "Output to stdout: 'json' or 'md'")

	// Customer/Application
	cmd.Flags().StringVar(&customerName, "customer", "", "Customer name")
	cmd.Flags().StringVar(&application, "application", "", "Application name")

	// Finding
	cmd.Flags().StringVar(&findingTitle, "finding-title", "", "Finding title")
	cmd.Flags().StringVar(&findingSeverity, "finding-severity", "", "Finding severity (Low, Moderate, High, Critical)")
	cmd.Flags().StringVar(&findingID, "finding-id", "", "Finding identifier")
	cmd.Flags().StringVar(&findingDate, "finding-date", "", "Finding detection date (YYYY-MM-DD)")

	// CVSS (optional)
	cmd.Flags().Float64Var(&cvssScore, "cvss-score", 0, "CVSS score")
	cmd.Flags().StringVar(&cvssVersion, "cvss-version", "", "CVSS version (e.g., 4.0)")
	cmd.Flags().StringVar(&cvssVector, "cvss-vector", "", "CVSS vector string")

	// SLA (type=sla only)
	cmd.Flags().IntVar(&slaTargetDays, "sla-target-days", 0, "SLA target days for remediation (type=sla)")
	cmd.Flags().StringVar(&slaOriginalDate, "sla-original-date", "", "Original SLA due date (YYYY-MM-DD) (type=sla)")
	cmd.Flags().StringVar(&slaNewDate, "sla-new-date", "", "New SLA due date (YYYY-MM-DD) (type=sla)")

	// Delay/Risk/Mitigation
	cmd.Flags().StringArrayVar(&delayReasons, "delay-reason", nil, "Delay reason (type=sla, can be specified multiple times)")
	cmd.Flags().StringVar(&riskAssessment, "risk", "", "Risk assessment text")
	cmd.Flags().StringArrayVar(&mitigations, "mitigation", nil, "Mitigation (can be specified multiple times)")
	cmd.Flags().StringVar(&remediation, "remediation", "", "Remediation plan")

	// Hardening (type=hardening only)
	cmd.Flags().StringVar(&rationale, "rationale", "", "Rationale for improvement (type=hardening)")
	cmd.Flags().StringVar(&targetDate, "target-date", "", "Target completion date (YYYY-MM-DD) (type=hardening)")

	// Sender
	cmd.Flags().StringVar(&senderName, "sender-name", "", "Sender name")
	cmd.Flags().StringVar(&senderTitle, "sender-title", "", "Sender title")
	cmd.Flags().StringVar(&senderTeam, "sender-team", "", "Sender team")
	cmd.Flags().StringVar(&senderCompany, "sender-company", "", "Sender company")
	cmd.Flags().StringVar(&senderEmail, "sender-email", "", "Sender email")
	cmd.Flags().StringVar(&senderPhone, "sender-phone", "", "Sender phone (optional)")

	// Milestones (optional)
	cmd.Flags().StringArrayVar(&milestones, "milestone", nil, "Milestone in 'phase:description:date:impact' format (repeatable)")

	// Approver (optional)
	cmd.Flags().StringVar(&approverName, "approver-name", "", "Approver name")
	cmd.Flags().StringVar(&approverTitle, "approver-title", "", "Approver title")
	cmd.Flags().StringVar(&approverDate, "approver-date", "", "Approval date (YYYY-MM-DD)")

	// Escalation Policy (optional)
	cmd.Flags().StringArrayVar(&escalationPolicy, "escalation", nil, "Escalation policy action (repeatable)")

	return cmd
}

func buildLetterFromFlags(
	letterType string,
	customerName, application string,
	findingTitle, findingSeverity, findingID, findingDate string,
	cvssScore float64, cvssVersion, cvssVector string,
	slaTargetDays int, slaOriginalDate, slaNewDate string,
	delayReasons []string, riskAssessment string, mitigations []string, remediation string,
	rationale, targetDate string,
	senderName, senderTitle, senderTeam, senderCompany, senderEmail, senderPhone string,
	milestones []string, approverName, approverTitle, approverDate string, escalationPolicy []string,
) (*Letter, error) {
	// Validate common required fields
	var missing []string
	if customerName == "" {
		missing = append(missing, "--customer")
	}
	if application == "" {
		missing = append(missing, "--application")
	}
	if findingTitle == "" {
		missing = append(missing, "--finding-title")
	}
	if findingSeverity == "" {
		missing = append(missing, "--finding-severity")
	}
	if findingID == "" {
		missing = append(missing, "--finding-id")
	}
	if findingDate == "" {
		missing = append(missing, "--finding-date")
	}
	if riskAssessment == "" {
		missing = append(missing, "--risk")
	}
	if len(mitigations) == 0 {
		missing = append(missing, "--mitigation")
	}
	if remediation == "" {
		missing = append(missing, "--remediation")
	}
	if senderName == "" {
		missing = append(missing, "--sender-name")
	}
	if senderTitle == "" {
		missing = append(missing, "--sender-title")
	}
	if senderTeam == "" {
		missing = append(missing, "--sender-team")
	}
	if senderCompany == "" {
		missing = append(missing, "--sender-company")
	}
	if senderEmail == "" {
		missing = append(missing, "--sender-email")
	}

	// Type-specific validation
	if letterType == TypeHardening {
		if rationale == "" {
			missing = append(missing, "--rationale")
		}
	} else {
		// SLA type
		if slaTargetDays == 0 {
			missing = append(missing, "--sla-target-days")
		}
		if slaOriginalDate == "" {
			missing = append(missing, "--sla-original-date")
		}
		if slaNewDate == "" {
			missing = append(missing, "--sla-new-date")
		}
		if len(delayReasons) == 0 {
			missing = append(missing, "--delay-reason")
		}
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}

	ltr := &Letter{
		SchemaVersion: SchemaVersion,
		Type:          letterType,
		Sender: Sender{
			Name:    senderName,
			Title:   senderTitle,
			Team:    senderTeam,
			Company: senderCompany,
			Email:   senderEmail,
			Phone:   senderPhone,
		},
		CustomerName: customerName,
		Application:  application,
		Finding: Finding{
			Title:      findingTitle,
			Severity:   findingSeverity,
			Identifier: findingID,
			DetectedOn: findingDate,
		},
		RiskAssessment:  riskAssessment,
		Mitigations:     mitigations,
		RemediationPlan: remediation,
	}

	// Type-specific fields
	if letterType == TypeHardening {
		ltr.Rationale = rationale
		ltr.TargetDate = targetDate
	} else {
		ltr.SLA = &SLA{
			TargetDays:      slaTargetDays,
			OriginalDueDate: slaOriginalDate,
			NewDueDate:      slaNewDate,
		}
		ltr.DelayReasons = delayReasons
	}

	if cvssScore > 0 && cvssVersion != "" {
		ltr.CVSS = &CVSS{
			Score:   cvssScore,
			Version: cvssVersion,
			Vector:  cvssVector,
		}
	}

	// Parse milestones from "phase:description:date:impact" format
	if len(milestones) > 0 {
		for _, m := range milestones {
			parts := strings.SplitN(m, ":", 4)
			if len(parts) != 4 {
				return nil, fmt.Errorf("invalid milestone format: %q (expected 'phase:description:date:impact')", m)
			}
			phase := 0
			if _, err := fmt.Sscanf(parts[0], "%d", &phase); err != nil {
				return nil, fmt.Errorf("invalid milestone phase: %q", parts[0])
			}
			ltr.Milestones = append(ltr.Milestones, Milestone{
				Phase:          phase,
				Description:    parts[1],
				TargetDate:     parts[2],
				CustomerImpact: parts[3],
			})
		}
	}

	// Set approver if name and title are provided
	if approverName != "" && approverTitle != "" {
		ltr.Approver = &Approver{
			Name:         approverName,
			Title:        approverTitle,
			ApprovalDate: approverDate,
		}
	}

	// Set escalation policy
	if len(escalationPolicy) > 0 {
		ltr.EscalationPolicy = escalationPolicy
	}

	ltr.SetSubjectFromFinding()

	return ltr, nil
}
