package govex

import (
	"github.com/grokify/gocharts/v2/data/table"
)

func TableColumnDefinitionSetSAST() table.ColumnDefinitionSet {
	return table.ColumnDefinitionSet{
		DefaultFormat: table.FormatString,
		Definitions: []table.ColumnDefinition{
			{
				Name:         FieldCategory,
				SourceName:   FieldCategory,
				DefaultValue: CategorySAST,
			},
			{
				Name:         FieldSeverity,
				SourceName:   FieldSeverity,
				DefaultValue: SeverityUnknown,
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
