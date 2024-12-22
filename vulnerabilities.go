package govex

import (
	"cmp"
	"slices"
	"sort"
	"strings"

	"github.com/grokify/mogo/type/slicesutil"

	"github.com/grokify/govex/cve20"
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

func (vs *Vulnerabilities) OrderdListMarkdownBytes(opts *ValueOpts) []byte {
	var out []byte
	lines := vs.OrderdListMarkdownLines(opts)
	for i, line := range lines {
		out = append(out, []byte(line)...)
		if i < len(lines)-1 {
			out = append(out, []byte("\n")...)
		}
	}
	return out
}

func (vs *Vulnerabilities) OrderdListMarkdownLines(opts *ValueOpts) []string {
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
