package govex

import (
	"github.com/grokify/gocharts/v2/data/table"
)

func (vs *Vulnerabilities) Table(colDefs table.ColumnDefinitionSet, opts *ValueOpts) (*table.Table, error) {
	t := table.NewTable("")
	t.LoadColumnDefinitionSet(colDefs)
	for _, v := range *vs {
		t.Rows = append(t.Rows, v.Values(colDefs.Definitions, opts))
	}
	return &t, nil
}

func TableColumnDefinitionSetSAST() table.ColumnDefinitionSet {
	return table.ColumnDefinitionSet{
		DefaultFormat: table.FormatString,
		Definitions: []table.ColumnDefinition{
			{
				Name:         FieldSeverity,
				SourceName:   FieldSeverity,
				DefaultValue: SeverityUnknown,
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
			{
				Name:       FieldLocationPath,
				SourceName: FieldLocationPath,
			},
			{
				Name:       FieldLocationLineStart,
				SourceName: FieldLocationLineStart,
				Format:     table.FormatInt,
			},
			{
				Name:       FieldLocationLineEnd,
				SourceName: FieldLocationLineEnd,
				Format:     table.FormatInt,
			},
		},
	}
}
