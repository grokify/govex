package jvex

import (
	"github.com/grokify/gocharts/v2/data/table"
)

func (vs *Vulnerabilities) Table(colDefs table.ColumnDefinitionSet, opts *ValueOpts) (*table.Table, error) {
	t := table.NewTable("")
	t.LoadColumnDefinitionSet(colDefs)
	colSourceNames, err := colDefs.Definitions.SourceNames(false, true)
	if err != nil {
		return nil, err
	}
	for _, v := range *vs {
		t.Rows = append(t.Rows, v.Values(colSourceNames, opts))
	}
	return &t, nil
}
