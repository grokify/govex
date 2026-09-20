package main

import (
	"fmt"

	"github.com/grokify/govex"
	"github.com/grokify/mogo/log/logutil"
)

func main() {
	f := "vulns.json"

	vset, err := govex.ReadFilesVulnerabilitiesSet(f)
	logutil.FatalErr(err)

	fmt.Printf("COUNT (%d)\n", len(vset.Vulnerabilities))

	vs, err := vset.Vulnerabilities.Dedupe()
	logutil.FatalErr(err)

	fmt.Printf("COUNT (%d)\n", len(vs))

	fmt.Println("DONE")
}
