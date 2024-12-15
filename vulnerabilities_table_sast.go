package jvex

import (
	"github.com/grokify/gocharts/v2/data/table"
)

func TableColumnDefinitionSetSAST() table.ColumnDefinitionSet {
	return table.ColumnDefinitionSet{
		DefaultFormat: table.FormatString,
		Definitions: []table.ColumnDefinition{
			{
				Name:         "Category",
				SourceName:   FieldCategory,
				DefaultValue: "SAST",
			},
			{
				Name:         "Severity",
				SourceName:   FieldSeverity,
				DefaultValue: SeverityUnknown,
			},
			{
				Name:       "Name",
				SourceName: FieldNameWithURL,
				Format:     table.FormatURL,
			},
			{
				Name:       "Description",
				SourceName: FieldDescription,
			},
			{
				Name:       "Location",
				SourceName: FieldLocationPath,
			},
			{
				Name:       "Start Line",
				SourceName: FieldLocationLineStart,
				Format:     table.FormatInt,
			},
			{
				Name:       "End Line",
				SourceName: FieldLocationLineEnd,
				Format:     table.FormatInt,
			},
		},
	}
}
