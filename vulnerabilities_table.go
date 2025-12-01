package govex

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/govex/severity"
	"github.com/grokify/mogo/pointer"
	"github.com/grokify/mogo/text/markdown"
)

func (vs *Vulnerabilities) Table(colDefs table.ColumnDefinitionSet, opts *ValueOptions) (*table.Table, error) {
	t := table.NewTable("")
	t.LoadColumnDefinitionSet(colDefs)
	for _, v := range *vs {
		t.Rows = append(t.Rows, v.Values(colDefs.Definitions, opts))
	}
	return &t, nil
}

func (vs *Vulnerabilities) TableFindingsOverdue(opts *ValueOptions, referenceTime time.Time) (*table.Table, error) {
	t := table.NewTable("")
	t.Columns = []string{
		"ID",
		"Name",
		"Severity",
		"Target Release",
		"Overdue Days"}
	t.FormatMap = map[int]string{
		0: table.FormatURL,
		3: table.FormatInt,
	}
	var sla severity.SLAPolicy
	if opts != nil && opts.SLAOptions != nil && opts.SLAOptions.SLAPolicy != nil {
		sla = *opts.SLAOptions.SLAPolicy
	} else {
		return nil, errors.New("sla policy cannot be nil")
	}

	for _, vn := range *vs {
		overdueDurationDays, err := sla.OverdueDays(vn.Severity, referenceTime.Sub(pointer.Dereference(vn.SLATimeStart)))
		if err != nil {
			return nil, err
		}
		t.Rows = append(t.Rows, []string{
			markdown.Linkify(pointer.Dereference(vn.WorkItemURL), pointer.Dereference(vn.WorkItemID)),
			strings.ReplaceAll(strings.Join(strings.Fields(vn.Name), " "), "|", "-"),
			vn.Severity,
			strings.ReplaceAll(strings.Join(strings.Fields(vn.VersionRemediationTarget), " "), "|", "-"),
			strconv.Itoa(overdueDurationDays),
		})
	}
	return &t, nil
}

func (vs *Vulnerabilities) TableSetSplitSeverity(colDefs table.ColumnDefinitionSet, sevCutoff string, sevInclWithHigher bool, name1, name2 string, addCountsToNames bool, opts *ValueOptions) (*table.TableSet, error) {
	if vfs, err := BuildVulnerabilitiesFiltersSplit(sevCutoff, sevInclWithHigher, name1, name2); err != nil {
		return nil, err
	} else {
		return vs.TableSet(colDefs, vfs, addCountsToNames, opts)
	}
}

func (vs *Vulnerabilities) TableSet(colDefs table.ColumnDefinitionSet, filters VulnerabilitiesFilters, addCountsToNames bool, opts *ValueOptions) (*table.TableSet, error) {
	ts := table.NewTableSet("")
	for i, fil := range filters {
		if vsFiltered, err := vs.FilterSeverities(fil.SeveritiesIncl); err != nil {
			return nil, err
		} else if tblFiltered, err := vsFiltered.Table(colDefs, opts); err != nil {
			return nil, err
		} else {
			name := strings.TrimSpace(fil.Name)
			if name == "" {
				name = fmt.Sprintf("Sheet %d", i+1)
			}
			if addCountsToNames {
				name += fmt.Sprintf(" (%d)", len(tblFiltered.Rows))
			}
			tblFiltered.Name = name
			if err := ts.Add(tblFiltered); err != nil {
				return nil, err
			}
		}
	}
	return ts, nil
}

func (vs *Vulnerabilities) WriteFileXLSX(filename, sheetname string, colDefs table.ColumnDefinitionSet, opts *ValueOptions) error {
	if tbl, err := vs.Table(colDefs, opts); err != nil {
		return err
	} else {
		return tbl.WriteXLSX(filename, sheetname)
	}
}

func (vs *Vulnerabilities) WriteFileXLSXSplitSeverity(filename string, colDefs table.ColumnDefinitionSet, sevCutoff, name1, name2 string, opts *ValueOptions) (int, int, error) {
	if sevCutoff != "" {
		ts, err := vs.TableSetSplitSeverity(
			colDefs,
			sevCutoff, true, name1, name2,
			true, opts)
		if err != nil {
			return -1, -1, err
		}
		lens := ts.LensOrdered()
		if len(lens) != 2 {
			return -1, -1, errors.New("error in `Vulnerabilities.WriteFileXLSXSplitSeverity`: lengths mismatch")
		}
		len1 := lens[0]
		len2 := lens[1]
		if err = ts.WriteXLSX(filename); err != nil {
			return len1, len2, err
		} else {
			return len1, len2, nil
		}
	} else if tbl, err := vs.Table(colDefs, opts); err != nil {
		return -1, -1, err
	} else {
		return len(tbl.Rows), -1, tbl.WriteXLSX(filename, name1)
	}
}

func TableColumnDefinitionSetSAST() table.ColumnDefinitionSet {
	return table.ColumnDefinitionSet{
		DefaultFormat: table.FormatString,
		Definitions: []table.ColumnDefinition{
			{
				Name:         FieldSeverity,
				SourceName:   FieldSeverity,
				DefaultValue: severity.SeverityUnknown,
			},
			{
				Name:         FieldCategory,
				SourceName:   FieldCategory,
				DefaultValue: CategorySAST,
			},
			{
				Name:       FieldName,
				SourceName: FieldNameWithURL,
				Format:     table.FormatURL,
			},
			{
				Name:       FieldReferenceURL,
				SourceName: FieldReferenceURL,
				Format:     table.FormatURL,
			},
			{
				Name:       FieldDescription,
				SourceName: FieldDescription,
			},
			{ // SAST
				Name:       FieldLocationPath,
				SourceName: FieldLocationPath,
			},
			{ // SAST
				Name:       FieldLocationLineStart,
				SourceName: FieldLocationLineStart,
				Format:     table.FormatInt,
			},
			{ // SAST
				Name:       FieldLocationLineEnd,
				SourceName: FieldLocationLineEnd,
				Format:     table.FormatInt,
			},
		},
	}
}

func TableColumnDefinitionSetSASTSCAReport() table.ColumnDefinitionSet {
	return table.ColumnDefinitionSet{
		DefaultFormat: table.FormatString,
		Definitions: []table.ColumnDefinition{
			{
				Name:         FieldSeverity,
				SourceName:   FieldSeverity,
				DefaultValue: severity.SeverityUnknown,
			},
			{
				Name:         FieldCategory,
				SourceName:   FieldCategory,
				DefaultValue: CategorySAST,
			},
			{
				Name:       FieldName,
				SourceName: FieldNameWithURL,
				Format:     table.FormatURL,
			},
			{
				Name:       FieldDescription,
				SourceName: FieldDescription,
			},
			{ // SAST
				Name:       FieldLocationPath,
				SourceName: FieldLocationPath,
			},
			{ // SAST
				Name:       FieldLocationLineStart,
				SourceName: FieldLocationLineStart,
				Format:     table.FormatInt,
			},
			{ // SAST
				Name:       FieldLocationLineEnd,
				SourceName: FieldLocationLineEnd,
				Format:     table.FormatInt,
			},
			{ // SCA
				Name:       FieldLibraryName,
				SourceName: FieldLibraryName,
			},
			{ // SCA
				Name:       FieldLibraryVersion,
				SourceName: FieldLibraryVersion,
			},
			{ // SCA
				Name:       FieldLibraryVersionFixed,
				SourceName: FieldLibraryVersionFixed,
			},
		},
	}
}

func TableColumnDefinitionSetSCA() table.ColumnDefinitionSet {
	return table.ColumnDefinitionSet{
		DefaultFormat: table.FormatString,
		Definitions: []table.ColumnDefinition{
			{
				Name:         FieldSeverity,
				SourceName:   FieldSeverity,
				DefaultValue: severity.SeverityUnknown,
			},
			{
				Name:         FieldCategory,
				SourceName:   FieldCategory,
				DefaultValue: CategorySAST,
			},
			{
				Name:       FieldName,
				SourceName: FieldNameWithURL,
				Format:     table.FormatURL,
			},
			{
				Name:       FieldReferenceURL,
				SourceName: FieldReferenceURL,
				Format:     table.FormatURL,
			},
			{
				Name:       FieldDescription,
				SourceName: FieldDescription,
			},
			{ // SCA
				Name:       FieldLibraryName,
				SourceName: FieldLibraryName,
			},
			{ // SCA
				Name:       FieldLibraryVersion,
				SourceName: FieldLibraryVersion,
			},
			{ // SCA
				Name:       FieldLibraryVersionFixed,
				SourceName: FieldLibraryVersionFixed,
			},
		},
	}
}

func TableColumnDefinitionSetSASTSCA() table.ColumnDefinitionSet {
	return table.ColumnDefinitionSet{
		DefaultFormat: table.FormatString,
		Definitions: []table.ColumnDefinition{
			{
				Name:         FieldSeverity,
				SourceName:   FieldSeverity,
				DefaultValue: severity.SeverityUnknown,
			},
			{
				Name:         FieldCategory,
				SourceName:   FieldCategory,
				DefaultValue: CategorySAST,
			},
			{
				Name:       FieldName,
				SourceName: FieldNameWithURL,
				Format:     table.FormatURL,
			},
			{
				Name:       FieldReferenceURL,
				SourceName: FieldReferenceURL,
				Format:     table.FormatURL,
			},
			{
				Name:       FieldDescription,
				SourceName: FieldDescription,
			},
			{ // SAST
				Name:       FieldLocationPath,
				SourceName: FieldLocationPath,
			},
			{ // SAST
				Name:       FieldLocationLineStart,
				SourceName: FieldLocationLineStart,
				Format:     table.FormatInt,
			},
			{ // SAST
				Name:       FieldLocationLineEnd,
				SourceName: FieldLocationLineEnd,
				Format:     table.FormatInt,
			},
			{ // SCA
				Name:       FieldLibraryName,
				SourceName: FieldLibraryName,
			},
			{ // SCA
				Name:       FieldLibraryVersion,
				SourceName: FieldLibraryVersion,
			},
			{ // SCA
				Name:       FieldLibraryVersionFixed,
				SourceName: FieldLibraryVersionFixed,
			},
		},
	}
}
