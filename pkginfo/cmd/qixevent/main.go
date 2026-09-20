package main

import (
	"fmt"

	"github.com/grokify/govex/pkginfo"
	"github.com/grokify/mogo/fmt/fmtutil"
)

func main() {
	infos := pkginfo.NPMQixHackEvenPkgInfosAll()
	fmtutil.MustPrintJSON(infos)
	strs := infos.Strings()
	fmtutil.MustPrintJSON(strs)
	for _, str := range strs {
		fmt.Println(str)
	}
}
