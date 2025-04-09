package severity

import (
	"time"

	"github.com/grokify/mogo/pointer"
)

type SLAOptions struct {
	// SLAStartDateFixed is used if there is a fixed starting date for severity findings.
	SLAStartDateFixed *time.Time
	SLAMap            *SLAMap
}

func (opts SLAOptions) DueDate(sev string, startTimeSoft, startTimeHard *time.Time) (*time.Time, error) {
	if opts.SLAMap == nil {
		return nil, nil
	} else if slaDur := opts.SLAMap.SeverityDuration(sev); slaDur == 0 {
		return nil, nil
	} else if startTimeHard != nil {
		return pointer.Pointer(startTimeHard.Add(slaDur)), nil
	} else if opts.SLAStartDateFixed != nil {
		return pointer.Pointer(opts.SLAStartDateFixed.Add(slaDur)), nil
	} else if startTimeSoft != nil {
		return pointer.Pointer(startTimeSoft.Add(slaDur)), nil
	} else {
		return nil, nil
	}
}
