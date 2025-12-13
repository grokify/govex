package severity

import (
	"errors"
	"os"
	"strconv"
	"strings"

	badge "github.com/essentialkaos/go-badge"
	"github.com/grokify/gocharts/v2/data/histogram"
	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/google-fonts/roboto"
)

type SeverityCountsSets struct {
	KeyName string
	Items   map[string]SeverityCountsSet
}

func NewSeverityCountsSets() *SeverityCountsSets {
	return &SeverityCountsSets{
		Items: map[string]SeverityCountsSet{},
	}
}

func (sets *SeverityCountsSets) Add(key, sev string, count int) {
	set, ok := sets.Items[key]
	if !ok {
		set = NewSeverityCountsSet()
	}
	if set.Histogram == nil {
		set.Histogram = histogram.NewHistogram("")
	}
	set.Histogram.Add(sev, count)
	sets.Items[key] = set
}

func (sets *SeverityCountsSets) Table(sevs []string) *table.Table {
	if len(sevs) == 0 {
		sevs = SeveritiesFinding()
	}
	tbl := table.NewTable("")
	tbl.Columns = []string{
		sets.KeyName,
	}
	tbl.FormatMap = map[int]string{
		-1: table.FormatInt,
		0:  table.FormatString}
	tbl.Columns = append(tbl.Columns, sevs...)
	for key, set := range sets.Items {
		row := []string{key}
		counts := set.Counts(sevs)
		for _, c := range counts {
			row = append(row, strconv.Itoa(c))
		}
		tbl.Rows = append(tbl.Rows, row)
	}
	return &tbl
}

type SeverityCountsSet struct {
	Histogram *histogram.Histogram
}

func NewSeverityCountsSet() SeverityCountsSet {
	return SeverityCountsSet{Histogram: histogram.NewHistogram("")}
}

func (set *SeverityCountsSet) Counts(sevs []string) []int {
	var out []int
	for _, sev := range sevs {
		if set.Histogram == nil {
			out = append(out, 0)
		} else if v, ok := set.Histogram.Items[sev]; ok {
			out = append(out, v)
		} else {
			out = append(out, 0)
		}
	}
	return out
}

func FuncShieldNameSeverity() func(sev string) (string, error) {
	return func(sev string) (string, error) {
		if sev == SeverityPlusNeedsRemediation {
			return SeverityPlusNeedsRemediation + " Vulns", nil
		}
		sev2, _, err := ParseSeverity(sev)
		if err != nil {
			return sev2, nil
		}
		return sev2 + " Vulns", nil
	}
}

func (sc SeverityCountsSet) WriteShields(sevs []string,
	fontSize int,
	sevCutoff string,
	fnFilepath func(sev string) (string, error),
	fnShieldName func(sev string) (string, error),
	perm os.FileMode,
) error {
	if sc.Histogram == nil {
		return errors.New("field SeverityCounts.Histogram cannot be nil")
	}
	g, err := badge.NewGeneratorFromBytes(roboto.RobotoRegular(), fontSize)
	if err != nil {
		return err
	}
	_, sevCutoffInt, err := ParseSeverity(sevCutoff)
	if err != nil {
		return err
	}

	needsRemediationCount := 0
	cutoffCount := 0

	sevInts, err := ParseSeverities(sevs)
	if err != nil {
		return err
	}

	for i, sev := range sevs {
		sevInt := sevInts[i]
		fp, err := fnFilepath(sev)
		if err != nil {
			return err
		}
		sevShieldName, err := fnShieldName(sev)
		if err != nil {
			return err
		}
		sevCount := sc.Histogram.BinValueOrDefault(sev, 0)
		clr, err := SeverityCountColorHex(sev, sevCutoff, sevCount)
		if err != nil {
			return err
		}
		b := g.GeneratePlastic(
			sevShieldName,
			strconv.Itoa(sevCount),
			clr)
		if err = os.WriteFile(fp, b, perm); err != nil {
			return err
		}
		if sevInt.NeedsRemediation() {
			needsRemediationCount += sevCount
		}
		if strings.TrimSpace(sevCutoff) != "" {
			if sevInt <= sevCutoffInt {
				cutoffCount += sevCount
			}
		} else {
			cutoffCount += sevCount
		}
	}

	clr := badge.COLOR_BRIGHTGREEN
	if cutoffCount > 0 {
		clr = badge.COLOR_RED
	} else if needsRemediationCount > 0 {
		clr = badge.COLOR_YELLOW
	}

	b := g.GeneratePlastic(
		SeverityPlusNeedsRemediation+" Vulns",
		strconv.Itoa(needsRemediationCount),
		clr)
	fp, err := fnFilepath(SeverityPlusNeedsRemediation)
	if err != nil {
		return err
	}
	if err = os.WriteFile(fp, b, perm); err != nil {
		return err
	}

	return nil
}

func SeverityCountColorHex(sev, sevCutoffIncl string, count int) (string, error) {
	if count <= 0 {
		return badge.COLOR_BRIGHTGREEN, nil
	}
	_, sevInt, err := ParseSeverity(sev)
	if err != nil {
		return "", err
	}
	sevCutoffIncl = strings.TrimSpace(sevCutoffIncl)
	if sevCutoffIncl == "" {
		return badge.COLOR_RED, nil
	} else if _, sevCutoffInclInt, err := ParseSeverity(sevCutoffIncl); err != nil {
		return "", err
	} else if sevInt <= sevCutoffInclInt {
		return badge.COLOR_RED, nil
	} else {
		return badge.COLOR_YELLOW, nil
	}
}
