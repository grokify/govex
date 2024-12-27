package govex

import (
	"cmp"
	"slices"
	"sort"
	"strings"

	"github.com/grokify/gocharts/v2/data/histogram"
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

func (vs *Vulnerabilities) OrderedListMarkdownBytes(opts *ValueOpts) []byte {
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

func (vs *Vulnerabilities) OrderedListMarkdownLines(opts *ValueOpts) []string {
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

func (vs *Vulnerabilities) CVE20Vulnerabilities() cve20.Vulnerabilities {
	var v []cve20.Vulnerability
	for _, ci := range *vs {
		cvi := ci.CVE()
		v = append(v, cve20.Vulnerability{CVE: &cvi})
	}
	return v
}
