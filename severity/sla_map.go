package severity

import (
	"fmt"
	"strconv"
	"time"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/mogo/time/timeutil"
)

const (
	// Status categories
	StatusWithinSLA      = "Within SLA"
	StatusApproachingSLA = "Approaching SLA"
	StatusOutOfSLA       = "Out of SLA"
)

// SLAMap provides a commen representation of SLAs by severity and day.
type SLAMap map[string]int64

type SLAPolicy struct {
	CriticalDays int64
	HighDays     int64
	MediumDays   int64
	LowDays      int64
}

// DueDate returns the due date for the severity given the SLA.
func (sla SLAPolicy) DueDate(sev string, startTime time.Time) (*time.Time, error) {
	if severityParsed, _, err := ParseSeverity(sev); err != nil {
		return nil, err
	} else {
		slaDuration := sla.SeveritySLADuration(severityParsed)
		due := startTime.Add(slaDuration)
		return &due, nil
	}
}

func (sla SLAPolicy) IsOverdue(sev string, age time.Duration) (overdueDuration time.Duration, isOverdue bool, err error) {
	if severityParsed, _, err := ParseSeverity(sev); err != nil {
		return 0, false, err
	} else {
		slaDuration := sla.SeveritySLADuration(severityParsed)
		if age > slaDuration {
			return age - slaDuration, true, nil
		} else {
			return 0, false, nil
		}
	}
}

func (sla SLAPolicy) Markdown() string {
	var out string
	sevs := []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	for _, sev := range sevs {
		slaDays := int64(0)
		switch sev {
		case SeverityCritical:
			slaDays = sla.CriticalDays
		case SeverityHigh:
			slaDays = sla.HighDays
		case SeverityMedium:
			slaDays = sla.MediumDays
		case SeverityLow:
			slaDays = sla.LowDays
		}
		suffix := "s"
		if slaDays == 1 {
			suffix = ""
		}
		out += fmt.Sprintf("* %s: %d day%s\n", sev, slaDays, suffix)
	}
	return out
}

func (sla SLAPolicy) OverdueDuration(sev string, age time.Duration) (time.Duration, error) {
	if severityParsed, _, err := ParseSeverity(sev); err != nil {
		return 0, err
	} else {
		slaDuration := sla.SeveritySLADuration(severityParsed)
		if age > slaDuration {
			return age - slaDuration, nil
		} else {
			return 0, nil
		}
	}
}

func (sla SLAPolicy) OverdueDays(sev string, age time.Duration) (int, error) {
	if d, err := sla.OverdueDuration(sev, age); err != nil {
		return 0, err
	} else {
		return int(d / timeutil.Day), nil
	}
}

func (sla SLAPolicy) SeveritySLADays(severity string) int64 {
	switch severity {
	case SeverityCritical:
		return sla.CriticalDays
	case SeverityHigh:
		return sla.HighDays
	case SeverityMedium:
		return sla.MediumDays
	case SeverityLow:
		return sla.LowDays
	default:
		return 0
	}
}

func (sla SLAPolicy) SeveritySLADuration(severity string) time.Duration {
	switch severity {
	case SeverityCritical:
		return time.Duration(sla.CriticalDays) * timeutil.Day
	case SeverityHigh:
		return time.Duration(sla.HighDays) * timeutil.Day
	case SeverityMedium:
		return time.Duration(sla.MediumDays) * timeutil.Day
	case SeverityLow:
		return time.Duration(sla.LowDays) * timeutil.Day
	default:
		return 0
	}
}

/*
func (slaMap SLAMap) SLAStatusOverdue(sev string, age time.Duration) (bool, error) {
	if severityParsed, _, err := ParseSeverity(sev); err != nil {
		return false, err
	} else if slaDays, ok := slaMap[severityParsed]; !ok {
		return false, fmt.Errorf("severity not found in SLA map (%s)", sev)
	} else {
		ageDays := timeutil.DurationDaysInt64(age)
		return ageDays > slaDays, nil
	}
}
*/

func (sla SLAPolicy) slaStatusOverdueTimes(severity string, startTime, evalTime time.Time) (bool, error) {
	// return slaMap.SLAStatusOverdue(severity, evalTime.Sub(startTime))
	_, isOverdue, err := sla.IsOverdue(severity, evalTime.Sub(startTime))
	return isOverdue, err
}

func (sla SLAPolicy) SLAStatusTimesString(severity string, startTime *time.Time, evalTime time.Time, unknownString string) (string, error) {
	if startTime == nil {
		return unknownString, nil
	} else if withinSLA, err := sla.slaStatusOverdueTimes(severity, *startTime, evalTime); err != nil {
		return unknownString, err
	} else if withinSLA {
		return StatusWithinSLA, nil
	} else {
		return StatusOutOfSLA, nil
	}
}

func (sla SLAPolicy) MustSLAStatusTimesString(severity string, startTime *time.Time, evalTime time.Time, unknownString string) string {
	if status, err := sla.SLAStatusTimesString(severity, startTime, evalTime, unknownString); err != nil {
		return unknownString
	} else {
		return status
	}
}

func (sla SLAPolicy) Table() *table.Table {
	tbl := table.NewTable("")
	tbl.Columns = []string{"Severity", "SLA"}
	tbl.FormatMap = map[int]string{1: table.FormatInt}
	suffix := " days"
	tbl.Rows = [][]string{
		{SeverityCritical, strconv.Itoa(int(sla.CriticalDays)) + suffix},
		{SeverityHigh, strconv.Itoa(int(sla.HighDays)) + suffix},
		{SeverityMedium, strconv.Itoa(int(sla.MediumDays)) + suffix},
		{SeverityLow, strconv.Itoa(int(sla.LowDays)) + suffix}}
	return &tbl
}
