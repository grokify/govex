package severity

import (
	"errors"
	"time"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/mogo/strconv/strconvutil"
	"github.com/grokify/mogo/time/timeutil"
	"github.com/grokify/mogo/type/maputil"
)

const (
	categoryAllAttribute = "_all"
	categoryAllDisplay   = "All"
)

type SeverityStatusSets struct {
	AllProperty string
	SLAMap      *SLAMap
	Data        map[string]SeverityStatusSet
}

func NewSeverityStatusSets() *SeverityStatusSets {
	return &SeverityStatusSets{
		AllProperty: categoryAllAttribute,
		Data:        map[string]SeverityStatusSet{},
	}
}

func (sets *SeverityStatusSets) Add(category, sev string, age time.Duration) error {
	if sets.SLAMap == nil {
		return errors.New("slaMap cannot be nil")
	}
	overdueDuration, _, err := sets.SLAMap.IsOverdue(sev, age)
	if err != nil {
		return err
	}
	allSet, ok := sets.Data[sets.AllProperty]
	if !ok {
		allSet = NewSeverityStatusSet()
	}
	allSet.Add(sev, overdueDuration)
	sets.Data[sets.AllProperty] = allSet
	if category != "" {
		catSet, ok := sets.Data[category]
		if !ok {
			allSet = NewSeverityStatusSet()
		}
		catSet.Add(sev, overdueDuration)
		sets.Data[category] = catSet
	}
	return nil
}

func (sets *SeverityStatusSets) Table() *table.Table {
	t := table.NewTable("")
	t.Columns = []string{
		"Category",
		"Severity",
		"Overdue Count",
		"Avg Overdue (days)",
		"Max Overdue (days)"}
	t.FormatMap = map[int]string{
		-1: table.FormatFloat,
		0:  table.FormatString,
		1:  table.FormatString,
		2:  table.FormatInt}
	if sets.AllProperty != "" {
		set, ok := sets.Data[sets.AllProperty]
		if ok {
			for sev, stats := range set.Data {
				row := []string{
					categoryAllDisplay,
					sev,
					strconvutil.Itoa(stats.OverdueCount),
					strconvutil.Itoa(int(stats.OverdueAverageDays)),
					strconvutil.Itoa(int(stats.OverdueMaximumDays)),
				}
				t.Rows = append(t.Rows, row)
			}
		}
	}
	catNames := maputil.Keys(sets.Data)
	for _, catName := range catNames {
		if catName == sets.AllProperty {
			continue
		}
		set, ok := sets.Data[catName]
		if !ok {
			continue
		}
		for sev, stats := range set.Data {
			row := []string{
				catName,
				sev,
				strconvutil.Itoa(stats.OverdueCount),
				strconvutil.Itoa(int(stats.OverdueAverageDays)),
				strconvutil.Itoa(int(stats.OverdueMaximumDays)),
			}
			t.Rows = append(t.Rows, row)
		}
	}
	return &t
}

type SeverityStatusSet struct {
	Data map[string]SeverityStatus
}

func NewSeverityStatusSet() SeverityStatusSet {
	return SeverityStatusSet{
		Data: map[string]SeverityStatus{},
	}
}

func (set *SeverityStatusSet) Add(sev string, overdueDuration time.Duration) {
	status, ok := set.Data[sev]
	if !ok {
		status = SeverityStatus{
			Severity: sev,
		}
	}
	status.OpenCount++
	if overdueDuration > 0 {
		status.OverdueCount++
		status.OverdueSum += overdueDuration
		if overdueDuration > status.OverdueMaximum {
			status.OverdueMaximum = overdueDuration
		}
		status.Inflate()
	} else {
		status.CompliantCount++
	}
	if set.Data == nil {
		set.Data = map[string]SeverityStatus{}
	}
	set.Data[sev] = status
}

type SeverityStatus struct {
	Severity           string
	OpenCount          uint32
	CompliantCount     uint32
	OverdueCount       uint32
	OverdueAverage     time.Duration
	OverdueAverageDays float64
	OverdueSum         time.Duration
	OverdueMaximum     time.Duration
	OverdueMaximumDays float64
}

func (stats *SeverityStatus) Inflate() {
	if stats.OverdueCount > 0 {
		stats.OverdueAverage = stats.OverdueSum / time.Duration(stats.OverdueCount)
	}
	stats.OverdueAverageDays = float64(stats.OverdueAverage / timeutil.Day)
	stats.OverdueMaximumDays = float64(stats.OverdueMaximum / timeutil.Day)
}
