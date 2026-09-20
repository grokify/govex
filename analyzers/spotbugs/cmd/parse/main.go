package main

import (
	"fmt"

	"github.com/grokify/mogo/fmt/fmtutil"
	"github.com/grokify/mogo/log/logutil"

	"github.com/grokify/govex"
	"github.com/grokify/govex/analyzers/spotbugs"
)

func main() {
	filename := "spotbugs-findsecbugs_raw.xml"

	bc, err := spotbugs.ParseBugCollectionFromFile(filename)
	logutil.FatalErr(err)

	logutil.FatalErr(fmtutil.PrintJSON(bc))
	fmt.Printf("COUNT (%d)\n", bc.BugInstanceCountAllFiles())

	vs, err := bc.ToGovexVulnerabilities(true)
	logutil.FatalErr(err)

	tbl, err := vs.Table(govex.TableColumnDefinitionSetSASTSCAReport(), nil)
	logutil.FatalErr(err)

	err = tbl.WriteXLSX("spotbugs-findsecbugs_raw.xlsx", "findings")
	logutil.FatalErr(err)

	logutil.FatalErr(fmtutil.PrintJSON(vs))
	fmt.Printf("COUNT (%d)\n", len(vs))

	fmt.Println("DONE")
}
