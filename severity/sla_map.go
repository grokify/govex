package severity

import (
	"fmt"
	"time"

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

func (slaMap SLAMap) SeverityDuration(severity string) time.Duration {
	if days, ok := slaMap[severity]; ok {
		return time.Duration(days) * timeutil.Day
	} else {
		return 0
	}
}

func (slaMap SLAMap) IsOverdue(sev string, age time.Duration) (overdueDuration time.Duration, isOverdue bool, err error) {
	if severityParsed, _, err := ParseSeverity(sev); err != nil {
		return 0, false, err
	} else if slaDays, ok := slaMap[severityParsed]; !ok {
		return 0, false, fmt.Errorf("severity not found in SLA map (%s)", sev)
	} else {
		slaDuration := timeutil.Day * time.Duration(slaDays)
		if age > slaDuration {
			return age - slaDuration, true, nil
		} else {
			return 0, false, nil
		}
	}
}

// DueDate returns the due date for the severity given the SLA.
func (slaMap SLAMap) DueDate(sev string, startTime time.Time) (*time.Time, error) {
	if severityParsed, _, err := ParseSeverity(sev); err != nil {
		return nil, err
	} else if days, ok := slaMap[severityParsed]; !ok {
		return nil, err
	} else {
		due := startTime.Add(time.Duration(days) * timeutil.Day)
		return &due, nil
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

func (slaMap SLAMap) slaStatusOverdueTimes(severity string, startTime, evalTime time.Time) (bool, error) {
	// return slaMap.SLAStatusOverdue(severity, evalTime.Sub(startTime))
	_, isOverdue, err := slaMap.IsOverdue(severity, evalTime.Sub(startTime))
	return isOverdue, err
}

func (slaMap SLAMap) SLAStatusTimesString(severity string, startTime *time.Time, evalTime time.Time, unknownString string) (string, error) {
	if startTime == nil {
		return unknownString, nil
	} else if withinSLA, err := slaMap.slaStatusOverdueTimes(severity, *startTime, evalTime); err != nil {
		return unknownString, err
	} else if withinSLA {
		return StatusWithinSLA, nil
	} else {
		return StatusOutOfSLA, nil
	}
}

func (slaMap SLAMap) MustSLAStatusTimesString(severity string, startTime *time.Time, evalTime time.Time, unknownString string) string {
	if status, err := slaMap.SLAStatusTimesString(severity, startTime, evalTime, unknownString); err != nil {
		return unknownString
	} else {
		return status
	}
}
