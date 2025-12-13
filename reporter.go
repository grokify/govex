package govex

import (
	"sort"
	"strings"
	"time"

	"github.com/grokify/mogo/type/slicesutil"
)

type Reporters []Reporter

func (repts Reporters) HaveKnownReporterType() bool {
	for _, rpt := range repts {
		if rpt.IsExternal != nil {
			return true
		}
	}
	return false
}

func (repts Reporters) HaveExternalReporter() bool {
	for _, rpt := range repts {
		if rpt.IsExternal != nil && *rpt.IsExternal {
			return true
		}
	}
	return false
}

func (repts Reporters) HaveInternalReporter() bool {
	for _, rpt := range repts {
		if rpt.IsExternal != nil && !*rpt.IsExternal {
			return true
		}
	}
	return false
}

func (repts Reporters) OrganizationNames() []string {
	var names []string
	for _, rpt := range repts {
		if orgName := strings.TrimSpace(rpt.OrganizationName); orgName != "" {
			names = append(names, orgName)
		}
	}
	names = slicesutil.Dedupe(names)
	sort.Strings(names)
	return names
}

type Reporter struct {
	OrganizationName string
	Date             *time.Time
	FindingDocument  string
	IsExternal       *bool // Reporter Type
}
