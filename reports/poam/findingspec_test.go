package poam

import (
	"testing"
	"time"

	"github.com/grokify/govex"
	"github.com/grokify/govex/severity"
	"github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/security"
)

func TestFromFindings(t *testing.T) {
	detected := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	findings := []findingspec.Finding{
		security.Vulnerability{
			ID:          "vuln-1",
			Title:       "Vulnerable log4j-core",
			Description: "Remote code execution via JNDI lookup.",
			CVEs:        []string{"CVE-2021-44228"},
			Severity:    findingspec.SeverityCritical,
			Status:      findingspec.StatusOpen,
			Package: &security.Package{
				Name:      "log4j-core",
				Version:   "2.14.1",
				Ecosystem: "maven",
			},
			Fix: &security.Fix{
				State:    security.FixStateFixed,
				Versions: []string{"2.17.1"},
			},
			Artifact: &security.Artifact{
				Image:       "app:latest",
				ImageDigest: "sha256:deadbeef",
			},
			DetectedAt: &detected,
		}.ToFinding(),
		security.Vulnerability{
			ID:          "vuln-2",
			Title:       "Vulnerable openssl",
			Description: "Buffer overflow.",
			CVEs:        []string{"CVE-2022-3602"},
			Severity:    findingspec.SeverityHigh,
			Status:      findingspec.StatusConfirmed,
			Package: &security.Package{
				Name:      "openssl",
				Version:   "3.0.0",
				Ecosystem: "apk",
			},
			Fix: &security.Fix{
				State:    security.FixStateNotFixed,
				Versions: nil,
			},
			Artifact: &security.Artifact{
				Image: "base:3.17",
			},
			DetectedAt: &detected,
		}.ToFinding(),
	}

	slaStart := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	opts := &govex.ValueOptions{
		DateFormat: time.DateOnly,
		SLAOptions: &severity.SLAOptions{
			SLAStartDateFixed: &slaStart,
			SLAPolicy: &severity.SLAPolicy{
				CriticalDays: 15,
				HighDays:     30,
				MediumDays:   90,
				LowDays:      180,
			},
		},
	}

	tbl, err := FromFindings(findings, opts, nil)
	if err != nil {
		t.Fatalf("FromFindings err: %v", err)
	}
	if len(tbl.Rows) != len(findings) {
		t.Fatalf("want %d rows, got %d", len(findings), len(tbl.Rows))
	}

	col := func(field POAMField) int {
		for i, c := range tbl.Columns {
			if c == string(field) {
				return i
			}
		}
		t.Fatalf("column not found: %s", field)
		return -1
	}

	cell := func(row int, field POAMField) string {
		return tbl.Rows[row][col(field)]
	}

	// Row 0: critical log4j finding.
	if got, want := cell(0, FieldWeaknessName), "Vulnerable log4j-core"; got != want {
		t.Errorf("row 0 WeaknessName = %q, want %q", got, want)
	}
	if got, want := cell(0, FieldCVE), "CVE-2021-44228"; got != want {
		t.Errorf("row 0 CVE = %q, want %q", got, want)
	}
	if got, want := cell(0, FieldAssetIdentifier), "sha256:deadbeef"; got != want {
		t.Errorf("row 0 AssetIdentifier = %q, want %q", got, want)
	}
	if got, want := cell(0, FieldOriginalRiskRating), "Critical"; got != want {
		t.Errorf("row 0 OriginalRiskRating = %q, want %q", got, want)
	}
	if got, want := cell(0, FieldControls), "RA-5"; got != want {
		t.Errorf("row 0 Controls = %q, want %q", got, want)
	}
	if got, want := cell(0, FieldOriginalDetectionDate), "2026-01-15"; got != want {
		t.Errorf("row 0 OriginalDetectionDate = %q, want %q", got, want)
	}
	// Critical SLA of 15 days from 2026-01-15.
	if got, want := cell(0, FieldScheduledCompletionDate), "2026-01-30"; got != want {
		t.Errorf("row 0 ScheduledCompletionDate = %q, want %q", got, want)
	}
	// Fixed fix state -> not a vendor dependency.
	if got, want := cell(0, FieldVendorDependency), "No"; got != want {
		t.Errorf("row 0 VendorDependency = %q, want %q", got, want)
	}
	if got, want := cell(0, FieldFalsePositive), "No"; got != want {
		t.Errorf("row 0 FalsePositive = %q, want %q", got, want)
	}

	// Row 1: high openssl finding (image, no digest).
	if got, want := cell(1, FieldAssetIdentifier), "base:3.17"; got != want {
		t.Errorf("row 1 AssetIdentifier = %q, want %q", got, want)
	}
	if got, want := cell(1, FieldOriginalRiskRating), "High"; got != want {
		t.Errorf("row 1 OriginalRiskRating = %q, want %q", got, want)
	}
	// Not-fixed fix state -> vendor dependency.
	if got, want := cell(1, FieldVendorDependency), "Yes"; got != want {
		t.Errorf("row 1 VendorDependency = %q, want %q", got, want)
	}
}

func TestFromFindingsNoSLA(t *testing.T) {
	detected := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	findings := []findingspec.Finding{
		security.Vulnerability{
			ID:       "vuln-1",
			Title:    "Vulnerable pkg",
			CVEs:     []string{"CVE-2021-44228"},
			Severity: findingspec.SeverityCritical,
			Status:   findingspec.StatusOpen,
			Package: &security.Package{
				Name:      "pkg",
				Version:   "1.0.0",
				Ecosystem: "npm",
			},
			DetectedAt: &detected,
		}.ToFinding(),
	}

	tbl, err := FromFindings(findings, &govex.ValueOptions{DateFormat: time.DateOnly}, nil)
	if err != nil {
		t.Fatalf("FromFindings err: %v", err)
	}
	if len(tbl.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(tbl.Rows))
	}

	col := func(field POAMField) int {
		for i, c := range tbl.Columns {
			if c == string(field) {
				return i
			}
		}
		t.Fatalf("column not found: %s", field)
		return -1
	}

	// Without an SLA policy, the scheduled completion date is empty.
	if got := tbl.Rows[0][col(FieldScheduledCompletionDate)]; got != "" {
		t.Errorf("ScheduledCompletionDate = %q, want empty", got)
	}
	if got, want := tbl.Rows[0][col(FieldWeaknessName)], "Vulnerable pkg"; got != want {
		t.Errorf("WeaknessName = %q, want %q", got, want)
	}
}
