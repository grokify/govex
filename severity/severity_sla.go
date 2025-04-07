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

func (slaMap SLAMap) SLAStatusOverdue(sev string, dur time.Duration) (bool, error) {
	severityParsed, _, err := ParseSeverity(sev)
	if err != nil {
		return false, err
	}
	if len(slaMap) == 0 {
		slaMap = SLAMapFedRAMP()
	}
	if slaDays, ok := slaMap[severityParsed]; !ok {
		return false, fmt.Errorf("severity not found in SLA map (%s)", sev)
	} else {
		ageDays := timeutil.DurationDaysInt64(dur)
		return ageDays > slaDays, nil
	}
}

func (slaMap SLAMap) slaStatusOverdueTimes(severity string, startTime, evalTime time.Time) (bool, error) {
	return slaMap.SLAStatusOverdue(severity, evalTime.Sub(startTime))
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
