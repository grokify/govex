package poam

import (
	"fmt"
	"slices"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/govex"
)

type POAMItem interface {
	POAMItemOpen() bool
	POAMItemClosed() bool
	POAMItemValue(field POAMField, opts *govex.ValueOptions, overrides func(field POAMField) (*string, error)) (string, error)
	POAMItemValues(fields []POAMField, opts *govex.ValueOptions, overrides func(field POAMField) (*string, error)) ([]string, error)
}

type RenderOptions struct {
	Defaults map[string]string
}

var POAMFields = []POAMField{
	FieldPOAMID,
	FieldControls,
	FieldWeaknessName,
	FieldWeaknessDescription,
	FieldWeaknessDetectorSource,
	FieldWeaknessSourceIdentifier,
	FieldAssetIdentifier,
	FieldPointOfContact,
	FieldResourcesRequired,
	FieldOverallRemediationPlan,
	FieldOriginalDetectionDate,
	FieldScheduledCompletionDate,
	FieldPlannedMilestones,
	FieldMilestoneChanges,
	FieldStatusDate,
	FieldVendorDependency,
	FieldLastVendorCheckInDate,
	FieldVendorDependentProductName,
	FieldOriginalRiskRating,
	FieldAdjustedRiskRating,
	FieldRiskAdjustment,
	FieldFalsePositive,
	FieldOperationalRequirement,
	FieldDeviationRationale,
	FieldSupportingDocuments,
	FieldComments,
	FieldAutoApprove,
	FieldBindingOperationalDirective2201Tracking,
	FieldBindingOperationalDirective2201DueDate,
	FieldCVE,
	FieldServiceName,
}

var POAMFieldsString = []string{}

func init() {
	for _, field := range POAMFields {
		POAMFieldsString = append(POAMFieldsString, string(field))
	}
}

type POAMField string

const (
	FieldPOAMID                                  POAMField = "POAMID"
	FieldControls                                          = "Controls"
	FieldWeaknessName                                      = "Weakness Name"
	FieldWeaknessDescription                               = "Weakness Description"
	FieldWeaknessDetectorSource                            = "Weakness Detector Source"
	FieldWeaknessSourceIdentifier                          = "Weakness Source Identifier"
	FieldAssetIdentifier                                   = "Asset Identifier"
	FieldPointOfContact                                    = "Point of Contact"
	FieldResourcesRequired                                 = "Resources Required"
	FieldOverallRemediationPlan                            = "Overall Remediation Plan"
	FieldOriginalDetectionDate                             = "Original Detection Date"
	FieldScheduledCompletionDate                           = "Scheduled Completion Date"
	FieldPlannedMilestones                                 = "Planned Milestones"
	FieldMilestoneChanges                                  = "Milestone Changes"
	FieldStatusDate                                        = "Status Date"
	FieldVendorDependency                                  = "Vendor Dependency"
	FieldLastVendorCheckInDate                             = "Last Vendor Check-in Date"
	FieldVendorDependentProductName                        = "Vendor Dependent Product Name"
	FieldOriginalRiskRating                                = "Original Risk Rating"
	FieldAdjustedRiskRating                                = "Adjusted Risk Rating"
	FieldRiskAdjustment                                    = "Risk Adjustment"
	FieldFalsePositive                                     = "False Positive"
	FieldOperationalRequirement                            = "Operational Requirement"
	FieldDeviationRationale                                = "Deviation Rationale"
	FieldSupportingDocuments                               = "Supporting Documents"
	FieldComments                                          = "Comments"
	FieldAutoApprove                                       = "Auto-Approve"
	FieldBindingOperationalDirective2201Tracking           = "Binding Operational Directive 22-01 tracking"
	FieldBindingOperationalDirective2201DueDate            = "Binding Operational Directive 22-01 Due Date"
	FieldCVE                                               = "CVE"
	FieldServiceName                                       = "Service Name"
)

func MapDescriptions() map[POAMField]string {
	return map[POAMField]string{
		FieldPOAMID: "Unique identifier for each POAM Item",
	}
}

func Table(items []POAMItem, opts *govex.ValueOptions, overrides func(field POAMField) (*string, error)) (*table.Table, error) {
	t := table.NewTable("")
	t.Columns = slices.Clone(POAMFieldsString)
	for _, item := range items {
		if !item.POAMItemOpen() {
			continue
		}
		if row, err := item.POAMItemValues(POAMFields, opts, overrides); err != nil {
			return nil, err
		} else if len(row) != len(t.Columns) {
			return nil, fmt.Errorf("poam row len (%d) and col len (%d) mismatch", len(row), len(t.Columns))
		} else {
			t.Rows = append(t.Rows, row)
		}
	}
	return &t, nil
}
