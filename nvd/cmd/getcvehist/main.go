package main

import (
	"context"
	"fmt"

	"github.com/grokify/govex/nvd"
	"github.com/grokify/mogo/fmt/fmtutil"
	"github.com/grokify/mogo/log/logutil"
)

func main() {
	cveID := "CVE-2025-6000"
	clt := nvd.Client{}
	resp, err := clt.GetCVEHitory(context.Background(), cveID)
	logutil.FatalErr(err)
	fmtutil.MustPrintJSON(resp)
	fmt.Println("DONE")
}

/*

CVE-2025-5999: Vault Root Namespace Operator May Elevate Token Privileges
CVE-2025-6000: Privileged Vault Operator May Execute Code on the Underlying Host
CVE-2025-6011: Timing Side-Channel in Userpass Authentication
CVE-2025-6037: Certificate Authentication Method Did Not Validate Common Name


https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId=CVE-2025-5999: Vault Root Namespace Operator May Elevate Token Privileges
1.20.0 excl

https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId=CVE-2025-6000: Privileged Vault Operator May Execute Code on the Underlying Host
1.20.1 excl


CVE-2025-6011: Timing Side-Channel in Userpass Authentication
1.20.0 excl

CVE-2025-6037: Certificate Authentication Method Did Not Validate Common Name
1.20.1
*/
