package exceptionrequest

import (
	"fmt"
	"strings"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/mogo/strconv/strconvutil"
)

type SERSet struct {
	Data map[string]Request
}

func NewSERSet() *SERSet {
	return &SERSet{Data: map[string]Request{}}
}

func (set *SERSet) Add(reqs ...Request) {
	for _, req := range reqs {
		set.Data[req.ID] = req
	}
}

func (set *SERSet) Table() *table.Table {
	tbl := table.NewTable("")
	tbl.Columns = []string{
		"Exception ID",
		"Implementation ID",
		"Aliases",
		"In Release",
		"Severity Environmental",
		"Severity Residual",
		"Severity Engineering",
		"Description",
		"Accepted Date",
		"SLA Date",
		"Exception Date Requested",
		"Exposes PII",
		"Enables Lateral Movement",
		"Requires Tenant Compromise",
		"Compensating Controls",
	}
	tbl.FormatMap = map[int]string{
		0:  table.FormatURL,
		1:  table.FormatURL,
		8:  table.FormatDate,
		9:  table.FormatDate,
		10: table.FormatDate,
	}

	for _, req := range set.Data {
		row := []string{
			req.ExceptionLink(),
			fmt.Sprintf("[%s](%s)", req.ID, req.ReferenceURL),
			strings.Join(req.Vulnerability.AliasIDs, ", "),
			strconvutil.Btoa(req.InRelease),
			req.Vulnerability.SeverityAppSecEnvironmental,
			req.Vulnerability.SeverityAppSecResidual,
			req.Vulnerability.SeverityEngineering,
			req.Description,
			"",
			"",
			req.ExceptionEndDateString(),
			req.ExposesPIIString(),
			req.EnablesLateralMovementString(),
			req.RequiresCompromisingTenantString(),
			req.CompensatingControlsDescription,
		}
		tbl.Rows = append(tbl.Rows, row)
	}
	return &tbl
}
