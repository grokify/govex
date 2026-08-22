package vulnreport

import (
	"fmt"
	"os"
	"strings"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/grokify/gocharts/v2/data/table"
)

// pdfMaxColumns is the maroto grid width; a findings table cannot render
// more columns than grid cells.
const pdfMaxColumns = 12

// PDF renders the report as PDF bytes using maroto. The findings table is
// limited to 12 columns (the maroto grid width); configure a narrower
// ColumnSet for wide reports.
func (r *Report) PDF() ([]byte, error) {
	findings, err := r.FindingsTable()
	if err != nil {
		return nil, err
	}
	if len(findings.Columns) > pdfMaxColumns {
		return nil, fmt.Errorf("findings table has %d columns; PDF supports at most %d — set Report.ColumnSet to a narrower column set",
			len(findings.Columns), pdfMaxColumns)
	}

	cfg := config.NewBuilder().
		WithPageNumber().
		WithLeftMargin(15).
		WithTopMargin(15).
		WithRightMargin(15).
		Build()
	m := maroto.New(cfg)

	if r.Classification != "" {
		m.AddRow(8, text.NewCol(pdfMaxColumns, strings.ToUpper(r.Classification), props.Text{
			Size:  10,
			Style: fontstyle.Bold,
			Align: align.Center,
		}))
	}
	m.AddRow(12, text.NewCol(pdfMaxColumns, r.Title, props.Text{
		Size:  18,
		Style: fontstyle.Bold,
		Align: align.Center,
	}))
	if r.Subtitle != "" {
		m.AddRow(8, text.NewCol(pdfMaxColumns, r.Subtitle, props.Text{
			Size:  12,
			Align: align.Center,
		}))
	}
	m.AddRow(6)

	if fields := r.metaFields(); len(fields) > 0 {
		pdfSectionHeader(m, "Metadata")
		for _, f := range fields {
			m.AddRow(6,
				text.NewCol(3, f.Label+":", props.Text{Size: 10, Style: fontstyle.Bold}),
				text.NewCol(9, f.Value, props.Text{Size: 10}),
			)
		}
		m.AddRow(6)
	}

	if r.Summary != "" {
		pdfSectionHeader(m, "Executive Summary")
		for _, para := range strings.Split(r.Summary, "\n\n") {
			if para = strings.TrimSpace(para); para != "" {
				m.AddRow(10, text.NewCol(pdfMaxColumns, para, props.Text{Size: 10}))
			}
		}
		m.AddRow(6)
	}

	pdfSectionHeader(m, "Severity Summary")
	pdfTable(m, r.SeverityTable())
	m.AddRow(6)

	pdfSectionHeader(m, "Findings")
	if len(findings.Rows) == 0 {
		m.AddRow(7, text.NewCol(pdfMaxColumns, "No findings.", props.Text{Size: 10}))
	} else {
		pdfTable(m, findings)
	}

	doc, err := m.Generate()
	if err != nil {
		return nil, fmt.Errorf("generating pdf: %w", err)
	}
	return doc.GetBytes(), nil
}

// WritePDFFile writes the report as a PDF file.
func (r *Report) WritePDFFile(filename string, perm os.FileMode) error {
	b, err := r.PDF()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, b, perm)
}

func pdfSectionHeader(m core.Maroto, title string) {
	m.AddRow(10, text.NewCol(pdfMaxColumns, title, props.Text{
		Size:  14,
		Style: fontstyle.Bold,
		Top:   2,
	}))
	m.AddRows(row.New(2))
}

// pdfTable renders a gocharts table onto the maroto grid, distributing the
// 12 grid cells across the table's columns.
func pdfTable(m core.Maroto, tbl *table.Table) {
	widths := pdfColumnWidths(len(tbl.Columns))
	var header []core.Col
	for i, name := range tbl.Columns {
		header = append(header, text.NewCol(widths[i], name, props.Text{
			Size:  9,
			Style: fontstyle.Bold,
			Align: align.Left,
		}))
	}
	m.AddRow(8, header...)

	for _, tblRow := range tbl.Rows {
		var cols []core.Col
		for i, val := range tblRow {
			if i >= len(widths) {
				break
			}
			cols = append(cols, text.NewCol(widths[i], val, props.Text{
				Size:  9,
				Align: align.Left,
			}))
		}
		m.AddRow(7, cols...)
	}
}

// pdfColumnWidths distributes the 12-cell maroto grid across n columns,
// assigning remainder cells to the leftmost columns.
func pdfColumnWidths(n int) []int {
	if n <= 0 {
		return nil
	}
	base := pdfMaxColumns / n
	rem := pdfMaxColumns % n
	widths := make([]int, n)
	for i := range widths {
		widths[i] = base
		if i < rem {
			widths[i]++
		}
	}
	return widths
}
