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
	FieldControls                                POAMField = "Controls"
	FieldWeaknessName                            POAMField = "Weakness Name"
	FieldWeaknessDescription                     POAMField = "Weakness Description"
	FieldWeaknessDetectorSource                  POAMField = "Weakness Detector Source"
	FieldWeaknessSourceIdentifier                POAMField = "Weakness Source Identifier"
	FieldAssetIdentifier                         POAMField = "Asset Identifier"
	FieldPointOfContact                          POAMField = "Point of Contact"
	FieldResourcesRequired                       POAMField = "Resources Required"
	FieldOverallRemediationPlan                  POAMField = "Overall Remediation Plan"
	FieldOriginalDetectionDate                   POAMField = "Original Detection Date"
	FieldScheduledCompletionDate                 POAMField = "Scheduled Completion Date"
	FieldPlannedMilestones                       POAMField = "Planned Milestones"
	FieldMilestoneChanges                        POAMField = "Milestone Changes"
	FieldStatusDate                              POAMField = "Status Date"
	FieldVendorDependency                        POAMField = "Vendor Dependency"
	FieldLastVendorCheckInDate                   POAMField = "Last Vendor Check-in Date"
	FieldVendorDependentProductName              POAMField = "Vendor Dependent Product Name"
	FieldOriginalRiskRating                      POAMField = "Original Risk Rating"
	FieldAdjustedRiskRating                      POAMField = "Adjusted Risk Rating"
	FieldRiskAdjustment                          POAMField = "Risk Adjustment"
	FieldFalsePositive                           POAMField = "False Positive"
	FieldOperationalRequirement                  POAMField = "Operational Requirement"
	FieldDeviationRationale                      POAMField = "Deviation Rationale"
	FieldSupportingDocuments                     POAMField = "Supporting Documents"
	FieldComments                                POAMField = "Comments"
	FieldAutoApprove                             POAMField = "Auto-Approve"
	FieldBindingOperationalDirective2201Tracking POAMField = "Binding Operational Directive 22-01 tracking"
	FieldBindingOperationalDirective2201DueDate  POAMField = "Binding Operational Directive 22-01 Due Date"
	FieldCVE                                     POAMField = "CVE"
	FieldServiceName                             POAMField = "Service Name"
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
