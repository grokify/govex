package govex

import (
	"slices"
	"strings"
	"time"

	"github.com/grokify/govex/severity"
	"github.com/grokify/mogo/encoding/jsonutil"
	"github.com/grokify/mogo/type/stringsutil"
)

type VulnerabilitiesFilters []VulnerabilitiesFilter

func (vfs VulnerabilitiesFilters) HasSeverityFullCoverage() bool {
	mb := severity.NewMapBool(false)
	for _, vf := range vfs {
		for _, sev := range vf.SeveritiesIncl {
			mb[sev] = true
		}
	}
	return mb.AllTrue(true)
}

func BuildVulnerabilitiesFiltersSplit(sevCutoff string, sevInclWithHigher bool, name1, name2 string) (VulnerabilitiesFilters, error) {
	inclWithHigher := false
	inclWithLower := false
	if sevInclWithHigher {
		inclWithHigher = true
	} else {
		inclWithLower = true
	}
	sevs1, err := severity.SeveritiesHigher(severity.SeveritiesAll(), sevCutoff, inclWithHigher)
	if err != nil {
		return VulnerabilitiesFilters{}, err
	}
	sevs2, err := severity.SeveritiesLower(severity.SeveritiesAll(), sevCutoff, inclWithLower)
	if err != nil {
		return VulnerabilitiesFilters{}, err
	}
	return VulnerabilitiesFilters{
		{
			Name:           name1,
			SeveritiesIncl: sevs1,
		},
		{
			Name:           name2,
			SeveritiesIncl: sevs2,
		},
	}, nil
}

type VulnerabilitiesFilter struct {
	Name           string
	SeveritiesIncl []string
}

func (vs *Vulnerabilities) FilterFunc(fnFilterIncl func(vn Vulnerability) (bool, error)) (Vulnerabilities, error) {
	out := Vulnerabilities{}
	for _, vni := range *vs {
		if incl, err := fnFilterIncl(vni); err != nil {
			return out, err
		} else if incl {
			out = append(out, vni)
		}
	}
	return out, nil
}

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

func (vs *Vulnerabilities) FilterSeverities(severitiesIncl []string) (Vulnerabilities, error) {
	return vs.FilterFunc(func(vn Vulnerability) (bool, error) {
		if slices.Index(severitiesIncl, vn.Severity) >= 0 {
			return true, nil
		} else {
			return false, nil
		}
	})
}

func (vs *Vulnerabilities) FilterSeveritiesHigher(sev string, incl bool) (Vulnerabilities, error) {
	if sevs, err := severity.SeveritiesHigher(severity.SeveritiesAll(), sev, incl); err != nil {
		return Vulnerabilities{}, err
	} else {
		return vs.FilterSeverities(sevs)
	}
}

func (vs *Vulnerabilities) FilterSeveritiesLower(sev string, incl bool) (Vulnerabilities, error) {
	if sevs, err := severity.SeveritiesLower(severity.SeveritiesAll(), sev, incl); err != nil {
		return Vulnerabilities{}, err
	} else {
		return vs.FilterSeverities(sevs)
	}
}

func (vs *Vulnerabilities) FilterSLAElapsed(slaMap SLAMap, compTime time.Time) Vulnerabilities {
	var out Vulnerabilities
	for _, vn := range *vs {
		if vn.SLAElapsed(slaMap, compTime) {
			out = append(out, vn)
		}
	}
	return out
}

func (vs *Vulnerabilities) FilterSLACompliant(slaMap SLAMap, compTime time.Time) Vulnerabilities {
	var out Vulnerabilities
	for _, vn := range *vs {
		if vn.SLACompliant(slaMap, compTime) {
			out = append(out, vn)
		}
	}
	return out
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

func (vs *Vulnerabilities) Dedupe() (Vulnerabilities, error) {
	var out Vulnerabilities
	seen := map[string]int{}
	for _, vn := range *vs {
		if vnsha, err := jsonutil.SHA512d256Base32(vn, rune(0)); err != nil {
			return out, err
		} else if _, ok := seen[vnsha]; ok {
			continue
		} else {
			out = append(out, vn)
			seen[vnsha]++
		}
	}
	return out, nil
}
