package main

import (
	"fmt"

	"github.com/grokify/govex/cve"
	"github.com/grokify/mogo/fmt/fmtutil"
	"github.com/grokify/mogo/type/slicesutil"
)

var junePOAM = `videoconversion@CVE-2022-49168
videoconversion@CVE-2022-49413
videoconversion@CVE-2022-49465
videoconversion@CVE-2023-52975
videoconversion@CVE-2024-47745
videoconversion@CVE-2024-49882
videoconversion@CVE-2024-50036
videoconversion@CVE-2024-50278
videoconversion@CVE-2024-50301
videoconversion@CVE-2025-21759
videoconversion@CVE-2025-21791
videoconversion@CVE-2025-21796
videoconversion@CVE-2025-21920
videoconversion@CVE-2025-22004`

func main() {
	ids := cve.ParseCVEIDs(cve.RawData)

	fmtutil.MustPrintJSON(ids)
	fmt.Printf("COUNT (%d)\n", len(ids))

	juneIDs := cve.ParseCVEIDs(junePOAM)
	fmtutil.MustPrintJSON(juneIDs)
	fmt.Printf("COUNT (%d)\n", len(juneIDs))

	res := slicesutil.SplitVenn2(ids, juneIDs)
	fmtutil.MustPrintJSON(res)

	fmt.Println("DONE")
}
