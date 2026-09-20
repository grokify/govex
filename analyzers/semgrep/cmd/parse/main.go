package main

import (
	"fmt"

	"github.com/grokify/govex"
	"github.com/grokify/govex/analyzers/semgrep"
	"github.com/grokify/govex/analyzers/spotbugs"
	"github.com/grokify/mogo/fmt/fmtutil"
	"github.com/grokify/mogo/log/logutil"
)

func main() {
	filename := "semgrep.json"
	out, err := semgrep.ParseJSONFromFile(filename)
	logutil.FatalErr(err)
	logutil.FatalErr(fmtutil.PrintJSON(out))
	fmt.Printf("COUNT (%d)\n", len(out.Results))

	vs, err := out.ToGovexVulnerabilities()
	logutil.FatalErr(err)

	{
		f := "../../../spotbugs/cmd/parse/spotbugs-findsecbugs_raw.xml"
		rpt, err := spotbugs.ParseBugCollectionFromFile(f)
		logutil.FatalErr(err)
		vs2, err := rpt.ToGovexVulnerabilities(true)
		logutil.FatalErr(err)
		vs = append(vs, vs2...)
	}

	tbl, err := vs.Table(govex.TableColumnDefinitionSetSASTSCAReport(), nil)
	logutil.FatalErr(err)

	err = tbl.WriteXLSX(filename+".xlsx", "findings")
	logutil.FatalErr(err)
	fmt.Println("DONE")
}
