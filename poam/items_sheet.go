package poam

import "github.com/grokify/gocharts/v2/data/table"

type POAMItem interface {
	POAMItemValue(field string, overrides func(field string) (*string, error)) (string, error)
	POAMItemValues(fields []string, overrides func(field string) (*string, error)) ([]string, error)
}

type RenderOptions struct {
	Defaults map[string]string
}

func Columns() []string {
	return []string{
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
}

const (
	FieldPOAMID                                  = "POAMID"
	FieldControls                                = "Controls"
	FieldWeaknessName                            = "Weakness Name"
	FieldWeaknessDescription                     = "Weakness Description"
	FieldWeaknessDetectorSource                  = "Weakness Detector Source"
	FieldWeaknessSourceIdentifier                = "Weakness Source Identifier"
	FieldAssetIdentifier                         = "Asset Identifier"
	FieldPointOfContact                          = "Point of Contact"
	FieldResourcesRequired                       = "Resources Required"
	FieldOverallRemediationPlan                  = "Overall Remediation Plan"
	FieldOriginalDetectionDate                   = "Original Detection Date"
	FieldScheduledCompletionDate                 = "Scheduled Completion Date"
	FieldPlannedMilestones                       = "Planned Milestones"
	FieldMilestoneChanges                        = "Milestone Changes"
	FieldStatusDate                              = "Status Date"
	FieldVendorDependency                        = "Vendor Dependency"
	FieldLastVendorCheckInDate                   = "Last Vendor Check-in Date"
	FieldVendorDependentProductName              = "Vendor Dependent Product Name"
	FieldOriginalRiskRating                      = "Original Risk Rating"
	FieldAdjustedRiskRating                      = "Adjusted Risk Rating"
	FieldRiskAdjustment                          = "Risk Adjustment"
	FieldFalsePositive                           = "False Positive"
	FieldOperationalRequirement                  = "Operational Requirement"
	FieldDeviationRationale                      = "Deviation Rationale"
	FieldSupportingDocuments                     = "Supporting Documents"
	FieldComments                                = "Comments"
	FieldAutoApprove                             = "Auto-Approve"
	FieldBindingOperationalDirective2201Tracking = "Binding Operational Directive 22-01 tracking"
	FieldBindingOperationalDirective2201DueDate  = "Binding Operational Directive 22-01 Due Date"
	FieldCVE                                     = "CVE"
	FieldServiceName                             = "Service Name"
)

func MapDescriptions() map[string]string {
	return map[string]string{
		FieldPOAMID: "Unique identifier for each POAM Item",
	}
}

func Table(items []POAMItem, overrides func(field string) (*string, error)) error {
	t := table.NewTable("")
	t.Columns = Columns()
	for _, item := range items {
		if row, err := item.POAMItemValues(t.Columns, overrides); err != nil {
			return err
		} else {
			t.Rows = append(t.Rows, row)
		}
	}
	return nil
}
