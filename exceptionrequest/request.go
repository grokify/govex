package exceptionrequest

import (
	"fmt"
	"strings"
	"time"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/mogo/strconv/strconvutil"
)

type Requests []Request

func (reqs Requests) IDsMap() map[string]int {
	m := map[string]int{}
	for _, req := range reqs {
		m[req.ID]++
	}
	return m
}

func (reqs Requests) Request(id string) (*Request, error) {
	for _, req := range reqs {
		if req.ID == id {
			return &req, nil
		}
	}
	return nil, fmt.Errorf("request id not found (%s)", id)
}

func (reqs Requests) Table() *table.Table {
	tbl := table.NewTable("")
	tbl.Columns = []string{
		"Exception ID",
		"Implementation ID",
		"Environmental Severity",
		"Residual Risk",
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
		0: table.FormatURL,
		1: table.FormatURL,
		5: table.FormatDate,
		6: table.FormatDate,
		7: table.FormatDate,
	}

	for _, req := range reqs {
		row := []string{
			fmt.Sprintf("[%s](%s)", req.ID, req.ExceptionURL),
			fmt.Sprintf("[%s](%s)", req.ID, req.ReferenceURL),
			req.Vulnerability.SeverityAppSecEnvironmental,
			req.Vulnerability.SeverityAppSecResidual,
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

type VulnerabilitiesSet struct {
	Data map[string]Vulnerability
}

func NewVulnerabilitiesSet() *VulnerabilitiesSet {
	return &VulnerabilitiesSet{Data: map[string]Vulnerability{}}
}

func (set *VulnerabilitiesSet) Add(vulns ...Vulnerability) {
	if set.Data == nil {
		set.Data = map[string]Vulnerability{}
	}
	for _, vuln := range vulns {
		set.Data[vuln.ID] = vuln
	}
}

type Vulnerabilities []Vulnerability

type Vulnerability struct {
	ID                          string
	AliasIDs                    []string
	ItemType                    string
	SeverityEngineering         string
	SeverityAppSecEnvironmental string
	SeverityAppSecResidual      string
	ReportedAppSec              bool
	ReportedEngineering         bool
	ReportedExceptionRequest    bool
	Parent                      *Vulnerability
}

type Request struct {
	ID                              string
	InRelease                       bool
	Vulnerability                   Vulnerability
	ApplicationDate                 *time.Time
	ExceptionEndDate                *time.Time
	Department                      string
	RequestorEmail                  string
	Description                     string
	ExposesPII                      *bool
	RequiresCompromisingTenant      *bool
	EnablesLateralMovement          *bool
	CompensatingControlsDescription string
	Risk                            string
	CVSSScore                       float32
	CVSSVersion                     float32
	ExceptionURL                    string
	ReferenceURL                    string
	IsClosed                        bool
}

func (req Request) ExceptionEndDateString() string {
	if req.ExceptionEndDate != nil {
		return req.ExceptionEndDate.Format(time.DateOnly)
	} else {
		return ""
	}
}

func (req Request) ExposesPIIString() string             { return Bptoa(req.ExposesPII) }
func (req Request) EnablesLateralMovementString() string { return Bptoa(req.EnablesLateralMovement) }
func (req Request) RequiresCompromisingTenantString() string {
	return Bptoa(req.RequiresCompromisingTenant)
}

func Bptoa(b *bool) string {
	if b == nil {
		return ""
	} else {
		return strconvutil.Btoa(*b)
	}
}

func (req Request) ExceptionLink() string {
	text := req.ID
	if u := strings.TrimSpace(req.ExceptionURL); u == "" {
		return text + " - no SER"
	} else {
		return fmt.Sprintf("[%s](%s)", text, u)
	}
}
