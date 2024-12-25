package govex

import (
	"fmt"
	"strings"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/govex/severity"
)

func (vs *Vulnerabilities) Table(colDefs table.ColumnDefinitionSet, opts *ValueOpts) (*table.Table, error) {
	t := table.NewTable("")
	t.LoadColumnDefinitionSet(colDefs)
	for _, v := range *vs {
		t.Rows = append(t.Rows, v.Values(colDefs.Definitions, opts))
	}
	return &t, nil
}

func (vs *Vulnerabilities) TableSetSplitSeverity(colDefs table.ColumnDefinitionSet, sevCutoff string, sevInclWithHigher bool, name1, name2 string, addCountsToNames bool, opts *ValueOpts) (*table.TableSet, error) {
	if vfs, err := BuildVulnerabilitiesFiltersSplit(sevCutoff, sevInclWithHigher, name1, name2); err != nil {
		return nil, err
	} else {
		return vs.TableSet(colDefs, vfs, addCountsToNames, opts)
	}
}

func (vs *Vulnerabilities) TableSet(colDefs table.ColumnDefinitionSet, filters VulnerabilitiesFilters, addCountsToNames bool, opts *ValueOpts) (*table.TableSet, error) {
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

func (vs *Vulnerabilities) WriteFileXLSX(filename, sheetname string, colDefs table.ColumnDefinitionSet, opts *ValueOpts) error {
	if tbl, err := vs.Table(colDefs, opts); err != nil {
		return err
	} else {
		return tbl.WriteXLSX(filename, sheetname)
	}
}

func (vs *Vulnerabilities) WriteFileXLSXSplitSeverity(filename string, colDefs table.ColumnDefinitionSet, sevCutoff, name1, name2 string, opts *ValueOpts) error {
	if sevCutoff != "" {
		if ts, err := vs.TableSetSplitSeverity(
			colDefs,
			sevCutoff, true, name1, name2,
			true, opts); err != nil {
			return err
		} else if err = ts.WriteXLSX(filename); err != nil {
			return err
		} else {
			return nil
		}
	} else {
		return vs.WriteFileXLSX(filename, name1, colDefs, opts)
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
