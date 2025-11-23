package severity

import (
	"slices"
	"strconv"
	"time"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/mogo/pointer"
	"github.com/grokify/mogo/type/maputil"
)

const (
	AgeBucketWithinSLA = "Within SLA"
	AgeBucket1To30     = "1-30"
	AgeBucket31To60    = "31-60"
	AgeBucket61To90    = "61-90"
	AgeBucket91To120   = "91-120"
	AgeBucket121To180  = "121-180"
	AgeBucket181To360  = "181-360"
	AgeBucket361Plus   = "361+"

	DaysOverdue = "Days Overdue"
)

type SeverityStats struct {
	Count0ToSLA   int
	Count1To30    int
	Count31To60   int
	Count61To90   int
	Count91To120  int
	Count121To180 int
	Count181To360 int
	Count361Plus  int
}

func (stats *SeverityStats) Add(slaPolicy SLAPolicy, sev string, age time.Duration) error {
	overdueDays, err := slaPolicy.OverdueDays(sev, age)
	if err != nil {
		return err
	}
	bucket := OverdueBucketByDays(overdueDays)
	switch bucket.Name {
	case AgeBucketWithinSLA:
		stats.Count0ToSLA++
	case AgeBucket1To30:
		stats.Count1To30++
	case AgeBucket31To60:
		stats.Count31To60++
	case AgeBucket61To90:
		stats.Count61To90++
	case AgeBucket91To120:
		stats.Count91To120++
	case AgeBucket121To180:
		stats.Count121To180++
	case AgeBucket181To360:
		stats.Count181To360++
	case AgeBucket361Plus:
		stats.Count361Plus++
	}
	return nil
}

func (stats *SeverityStats) AddStats(s SeverityStats) {
	stats.Count0ToSLA += s.Count0ToSLA
	stats.Count1To30 += s.Count1To30
	stats.Count31To60 += s.Count31To60
	stats.Count61To90 += s.Count61To90
	stats.Count91To120 += s.Count91To120
	stats.Count121To180 += s.Count121To180
	stats.Count181To360 += s.Count181To360
	stats.Count361Plus += s.Count361Plus
}

func (stats *SeverityStats) Strings(label *string, addSumOverdue, addTotal bool) []string {
	var out []string
	if label != nil {
		out = append(out, *label)
	}
	out = append(out,
		strconv.Itoa(stats.Count0ToSLA),
		strconv.Itoa(stats.Count1To30),
		strconv.Itoa(stats.Count31To60),
		strconv.Itoa(stats.Count61To90),
		strconv.Itoa(stats.Count91To120),
		strconv.Itoa(stats.Count121To180),
		strconv.Itoa(stats.Count181To360),
		strconv.Itoa(stats.Count361Plus),
	)
	if addSumOverdue {
		out = append(out, strconv.Itoa(stats.Sum()-stats.Count0ToSLA))
	}
	if addTotal {
		out = append(out, strconv.Itoa(stats.Sum()))
	}
	return out
}

func (stats *SeverityStats) Sum() int {
	return stats.Count0ToSLA +
		stats.Count1To30 +
		stats.Count31To60 +
		stats.Count61To90 +
		stats.Count91To120 +
		stats.Count121To180 +
		stats.Count181To360 +
		stats.Count361Plus
}

type AgeBucket struct {
	Name    string
	MaxDays int
}

func AgeBuckets() []AgeBucket {
	return []AgeBucket{
		{Name: AgeBucketWithinSLA, MaxDays: 0},
		{Name: AgeBucket1To30, MaxDays: 30},
		{Name: AgeBucket31To60, MaxDays: 60},
		{Name: AgeBucket61To90, MaxDays: 90},
		{Name: AgeBucket91To120, MaxDays: 120},
		{Name: AgeBucket121To180, MaxDays: 60},
		{Name: AgeBucket181To360, MaxDays: 90},
		{Name: AgeBucket361Plus, MaxDays: 120},
	}
}

func OverdueBucketByDays(days int) AgeBucket {
	buckets := AgeBuckets()
	for _, bucket := range buckets {
		if days <= bucket.MaxDays {
			return bucket
		}
	}
	return buckets[len(buckets)-1]
}

type SeverityStatsSet struct {
	Items map[string]SeverityStats
	Order []string
}

func NewSeverityStatsSet() SeverityStatsSet {
	return SeverityStatsSet{Items: map[string]SeverityStats{}}
}

func (set *SeverityStatsSet) Add(slaPolicy SLAPolicy, key, sev string, age time.Duration) error {
	stats := SeverityStats{}
	if _, ok := set.Items[key]; ok {
		stats = set.Items[key]
	}
	if err := stats.Add(slaPolicy, sev, age); err != nil {
		return err
	}
	set.Items[key] = stats
	return nil
}

func (set *SeverityStatsSet) Sum() SeverityStats {
	sum := SeverityStats{}
	for _, v := range set.Items {
		sum.AddStats(v)
	}
	return sum
}

func (set *SeverityStatsSet) Table() *table.Table {
	tbl := table.NewTable("")
	// daysOverdueSuffix := " " + DaysOverdue
	daysOverdueSuffix := ""
	tbl.Columns = []string{
		"Module",
		AgeBucketWithinSLA + daysOverdueSuffix,
		AgeBucket1To30 + daysOverdueSuffix,
		AgeBucket31To60 + daysOverdueSuffix,
		AgeBucket61To90 + daysOverdueSuffix,
		AgeBucket91To120 + daysOverdueSuffix,
		AgeBucket121To180 + daysOverdueSuffix,
		AgeBucket181To360 + daysOverdueSuffix,
		AgeBucket361Plus + daysOverdueSuffix,
		"Overdue",
		"Total"}
	tbl.FormatMap = map[int]string{
		-1: table.FormatInt,
		0:  table.FormatString}

	var keys []string
	if len(set.Order) > 0 {
		keys = slices.Clone(set.Order)
	} else {
		keys = maputil.Keys(set.Items)
	}
	for _, key := range keys {
		if stats, ok := set.Items[key]; !ok {
			continue
		} else {
			tbl.Rows = append(tbl.Rows, stats.Strings(pointer.Pointer(key), true, true))
		}
	}
	statsSum := set.Sum()
	tbl.Rows = append(tbl.Rows, statsSum.Strings(pointer.Pointer("Total"), true, true))
	return &tbl
}
