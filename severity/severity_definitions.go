package severity

import "github.com/grokify/gocharts/v2/data/table"

func SeverityToScoreTable() *table.Table {
	tbl := table.NewTable("")
	tbl.Columns = []string{"Rating", "CVSS Score"}
	tbl.Rows = [][]string{
		{SeverityNone, "0.0"},
		{SeverityLow, "1.0 - 3.9"},
		{SeverityMedium, "4.0 - 6.9"},
		{SeverityHigh, "7.0 - 8.9"},
		{SeverityCritical, "9.0 - 10.0"},
	}
	return &tbl
}

func SeverityToScoreTableMarkdown(descOnTop bool) string {
	t := SeverityToScoreTable()
	mk := t.Markdown("\n", true)
	if descOnTop {
		return "This is an industry standard and can be found on the [FIRST website](https://www.first.org/cvss/v3-1/specification-document).\n\n" + mk
	} else {
		return mk + "\n\nThe above is what is defined within the CVSS documentation, which can be found on the [FIRST website](https://www.first.org/cvss/v3-1/specification-document)."
	}
}
