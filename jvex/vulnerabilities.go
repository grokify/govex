package jvex

import (
	"cmp"
	"slices"
	"sort"
	"strings"

	"github.com/grokify/mogo/type/slicesutil"
	"github.com/grokify/mogo/type/stringsutil"
	"github.com/grokify/vex/cve20"
)

type Vulnerabilities []Vulnerability

// FilterFixedInVersion returns a filtered subset with a fix version match, including empty string.
func (js *Vulnerabilities) FilterFixedInVersion(fixVersions []string, severity string) (Vulnerabilities, error) {
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
	return js.FilterFunc(fnIncl)
}

func (js *Vulnerabilities) FilterFunc(fnFilter func(j Vulnerability) (bool, error)) (Vulnerabilities, error) {
	out := Vulnerabilities{}
	for _, ji := range *js {
		if incl, err := fnFilter(ji); err != nil {
			return out, err
		} else if incl {
			out = append(out, ji)
		}
	}
	return out, nil
}

// FilterFixedInVersion returns a filtered subset with a fix version match, including empty string.
func (js *Vulnerabilities) FilterFixedInVersionAge(fixVersion, baseSeverity string, slaDays uint, slaElapsed bool) Vulnerabilities {
	fixVersion = strings.TrimSpace(fixVersion)
	baseSeverity = strings.TrimSpace(baseSeverity)
	out := Vulnerabilities{}
	for _, ci := range *js {
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

func (js *Vulnerabilities) IDs(unique bool) []string {
	var ids []string
	for _, ci := range *js {
		ids = append(ids, ci.ID)
	}
	if unique {
		ids = slicesutil.Dedupe(ids)
	}
	sort.Strings(ids)
	return ids
}

func (js *Vulnerabilities) OrderdListMarkdownBytes(opts *ValueOpts) []byte {
	var out []byte
	lines := js.OrderdListMarkdownLines(opts)
	for i, line := range lines {
		out = append(out, []byte(line)...)
		if i < len(lines)-1 {
			out = append(out, []byte("\n")...)
		}
	}
	return out
}

func (js *Vulnerabilities) OrderdListMarkdownLines(opts *ValueOpts) []string {
	var lines []string
	for _, ji := range *js {
		parts := []string{
			"1.",
			ji.Value(FieldID, "", opts),
			ji.Value(FieldSeverity, "", opts),
			ji.Value(FieldSLAOpenStatus, "", opts),
			ji.Value(FieldTitleAndDesc, "", opts),
			ji.Value(FieldAcceptedTimeRFC3339, "", opts),
			ji.Value(FieldFixVersion, "", opts),
		}
		lines = append(lines, strings.Join(parts, " "))
	}
	return lines
}

func (js *Vulnerabilities) SortByID() {
	slices.SortFunc(*js, func(a, b Vulnerability) int {
		return cmp.Compare(a.ID, b.ID)
	})
}

func (js *Vulnerabilities) CVE20Vulnerabilities() cve20.Vulnerabilities {
	var v []cve20.Vulnerability
	for _, ci := range *js {
		cvi := ci.CVE()
		v = append(v, cve20.Vulnerability{CVE: &cvi})
	}
	return v
}

func (js *Vulnerabilities) WriteXLSX(filename string, vopts *ValueOpts) error {
	t := js.Table(vopts)
	return t.WriteXLSX(filename, "cves")
}
