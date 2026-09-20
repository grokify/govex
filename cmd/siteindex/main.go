package main

import (
	"fmt"

	"github.com/grokify/mogo/log/logutil"

	"github.com/grokify/govex/reports/sitewriter"
)

func main() {
	err := sitewriter.CmdSiteWriteHomeRun()
	logutil.FatalErr(err)

	fmt.Println("DONE")
}
