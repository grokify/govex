package govex

import (
	"cmp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grokify/gocharts/v2/data/histogram"
	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/mogo/type/maputil"
	"github.com/grokify/mogo/type/slicesutil"
	"github.com/grokify/mogo/type/stringsutil"

	"github.com/grokify/govex/cve20"
	"github.com/grokify/govex/severity"
)

type Vulnerabilities []Vulnerability

func (vs *Vulnerabilities) IDs(unique bool) []string {
	var ids []string
	for _, ci := range *vs {
		ids = append(ids, ci.ID)
	}
	if unique {
		ids = slicesutil.Dedupe(ids)
	}
	sort.Strings(ids)
	return ids
}

func (vs *Vulnerabilities) Len() int {
	return len(*vs)
}

func (vs *Vulnerabilities) LenFunc(fnFilter func(v Vulnerability) (bool, error)) (int, error) {
	var count int
	for _, vn := range *vs {
		if incl, err := fnFilter(vn); err != nil {
			return -1, err
		} else if incl {
			count++
		}
	}
	return count, nil
}

func (vs *Vulnerabilities) LenSeverities(severitiesIncl ...string) (int, error) {
	severitiesIncl = stringsutil.SliceCondenseSpace(severitiesIncl, true, false)
	if len(severitiesIncl) == 0 {
		return 0, nil
	}
	sevMap, err := severity.NewSeverityMapCVSSSeveritiesOnly(severitiesIncl)
	if err != nil {
		return -1, err
	}
	return vs.LenFunc(func(vn Vulnerability) (bool, error) {
		_, ok := sevMap[vn.Severity]
		return ok, nil
	})
}

func (vs *Vulnerabilities) Modules(dedupe, sortAsc bool) []string {
	var modules []string
	for _, vn := range *vs {
		modules = append(modules, vn.Module)
	}
	if dedupe {
		modules = slicesutil.Dedupe(modules)
	}
	if sortAsc {
		sort.Strings(modules)
	}
	return modules
}

func (vs *Vulnerabilities) OrderedListMarkdownBytes(opts *ValueOptions) []byte {
	var out []byte
	lines := vs.OrderedListMarkdownLines(opts)
	for i, line := range lines {
		out = append(out, []byte(line)...)
		if i < len(lines)-1 {
			out = append(out, []byte("\n")...)
		}
	}
	return out
}

func (vs *Vulnerabilities) OrderedListMarkdownLines(opts *ValueOptions) []string {
	var lines []string
	for _, ji := range *vs {
		parts := []string{
			"1.",
			ji.Value(FieldID, "", opts),
			ji.Value(FieldSeverity, "", opts),
			ji.Value(FieldSLAOpenStatus, "", opts),
			ji.Value(FieldNameAndDesc, "", opts),
			ji.Value(FieldAcceptedTimeRFC3339, "", opts),
			ji.Value(FieldFixVersion, "", opts),
		}
		lines = append(lines, strings.Join(parts, " "))
	}
	return lines
}

func (vs *Vulnerabilities) SeverityHistogram() histogram.Histogram {
	h := histogram.NewHistogram("")
	h.Order = severity.SeveritiesAll()
	for _, vn := range *vs {
		h.Add(vn.Severity, 1)
	}
	h.Order = severity.SeveritiesAll()
	return *h
}

func (vs *Vulnerabilities) SeverityCounts() maputil.Records {
	h := vs.SeverityHistogram()
	return h.ItemValuesOrdered()
}

func (vs *Vulnerabilities) SeverityCountsString(sep string) string {
	recs := vs.SeverityCounts()
	return recs.String(sep)
}

func (vs *Vulnerabilities) SortByID() {
	slices.SortFunc(*vs, func(a, b Vulnerability) int {
		return cmp.Compare(a.ID, b.ID)
	})
}

func (vs *Vulnerabilities) SeverityStatsSetByModule(slaPolicy severity.SLAPolicy, slaCalcTime time.Time, unknownModule string) (severity.SeverityStatsSet, error) {
	statsSet := severity.NewSeverityStatsSet()
	for _, vn := range *vs {
		if vn.SLATimeStart == nil {
			continue
		} else if vn.SLATimeStart.Before(slaCalcTime) {
			statsSet.Add(slaPolicy, vn.Module, vn.Severity, slaCalcTime.Sub(*vn.SLATimeStart))
		}
	}
	return statsSet, nil
}

func (vs *Vulnerabilities) SeverityStatsSetBySeverity(slaPolicy severity.SLAPolicy, slaCalcTime time.Time, unknownModule string) (severity.SeverityStatsSet, error) {
	statsSet := severity.NewSeverityStatsSet()
	statsSet.Order = []string{
		severity.SeverityCritical,
		severity.SeverityHigh,
		severity.SeverityMedium,
		severity.SeverityLow}
	for _, vn := range *vs {
		if vn.SLATimeStart == nil {
			continue
		} else if vn.SLATimeStart.Before(slaCalcTime) {
			statsSet.Add(slaPolicy, vn.Severity, vn.Severity, slaCalcTime.Sub(*vn.SLATimeStart))
		}
	}
	return statsSet, nil
}

func (vs *Vulnerabilities) SortBySLATimeStart() {
	sort.Slice(*vs, func(i, j int) bool {
		t1, t2 := (*vs)[i].SLATimeStart, (*vs)[j].SLATimeStart

		// Treat nil as earliest; adjust if you want different behavior.
		if t1 == nil && t2 == nil {
			return false
		}
		if t1 == nil {
			return true
		}
		if t2 == nil {
			return false
		}
		return t1.Before(*t2)
	})
}

func (vs *Vulnerabilities) TableSeverities(componentName string) *table.Table {
	tbl := table.NewTable("")
	tbl.Columns = []string{
		componentName,
		severity.SeverityCritical,
		severity.SeverityHigh,
		severity.SeverityMedium,
		severity.SeverityLow,
		"Overdue Days"}
	allCounts := vs.SeverityHistogram()
	row := []string{
		"All",
		strconv.Itoa(allCounts.GetOrDefault(severity.SeverityCritical, 0)),
		strconv.Itoa(allCounts.GetOrDefault(severity.SeverityHigh, 0)),
		strconv.Itoa(allCounts.GetOrDefault(severity.SeverityMedium, 0)),
		strconv.Itoa(allCounts.GetOrDefault(severity.SeverityLow, 0)),
	}
	tbl.Rows = append(tbl.Rows, row)
	hset := histogram.NewHistogramSet("")
	for _, v := range *vs {
		hset.Add(v.Module, v.Severity, 1)
	}
	moduleNames := hset.ItemNames()
	for _, moduleName := range moduleNames {
		moduleHist, ok := hset.Items[moduleName]
		if ok {
			tbl.Rows = append(tbl.Rows, []string{
				moduleName,
				strconv.Itoa(moduleHist.GetOrDefault(severity.SeverityCritical, 0)),
				strconv.Itoa(moduleHist.GetOrDefault(severity.SeverityHigh, 0)),
				strconv.Itoa(moduleHist.GetOrDefault(severity.SeverityMedium, 0)),
				strconv.Itoa(moduleHist.GetOrDefault(severity.SeverityLow, 0)),
			})
		}
	}
	return &tbl
}

func (vs *Vulnerabilities) CVE20Vulnerabilities() cve20.Vulnerabilities {
	var v []cve20.Vulnerability
	for _, ci := range *vs {
		cvi := ci.CVE()
		v = append(v, cve20.Vulnerability{CVE: &cvi})
	}
	return v
}

func (vs *Vulnerabilities) FieldValues(fieldName, def string, opts *ValueOptions) []string {
	var out []string
	for _, vn := range *vs {
		out = append(out, vn.Value(fieldName, def, opts))
	}
	return stringsutil.SliceCondenseSpace(out, true, true)
}
