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
