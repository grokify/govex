package govex

import (
	"cmp"
	"slices"
	"sort"
	"strings"

	"github.com/grokify/mogo/type/slicesutil"
	"github.com/grokify/mogo/type/stringsutil"

	"github.com/grokify/govex/cve20"
)

type Vulnerabilities []Vulnerability

// FilterFixedInVersion returns a filtered subset with a fix version match, including empty string.
func (vs *Vulnerabilities) FilterFixedInVersion(fixVersions []string, severity string) (Vulnerabilities, error) {
	fixVersions = stringsutil.SliceCondenseSpace(fixVersions, true, true)
	severity = strings.TrimSpace(severity)
	fnIncl := func(jv Vulnerability) (bool, error) {
		verExcl := strings.TrimSpace(jv.VersionEndExcluding)
		if !slices.Contains(fixVersions, verExcl) {
			return false, nil
		}
		if severity != "" && severity != jv.Severity {
			return false, nil
		} else {
			return true, nil
		}
	}
	return vs.FilterFunc(fnIncl)
}

func (vs *Vulnerabilities) FilterFunc(fnFilter func(j Vulnerability) (bool, error)) (Vulnerabilities, error) {
	out := Vulnerabilities{}
	for _, ji := range *vs {
		if incl, err := fnFilter(ji); err != nil {
			return out, err
		} else if incl {
			out = append(out, ji)
		}
	}
	return out, nil
}

// FilterFixedInVersion returns a filtered subset with a fix version match, including empty string.
func (vs *Vulnerabilities) FilterFixedInVersionAge(fixVersion, baseSeverity string, slaDays uint, slaElapsed bool) Vulnerabilities {
	fixVersion = strings.TrimSpace(fixVersion)
	baseSeverity = strings.TrimSpace(baseSeverity)
	out := Vulnerabilities{}
	for _, ci := range *vs {
		verExcl := strings.TrimSpace(ci.VersionEndExcluding)
		if verExcl != fixVersion {
			continue
		}
		if baseSeverity != "" && baseSeverity != ci.Severity {
			continue
		}
	}
	return out
}

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
