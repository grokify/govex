package govex

import (
	"time"

	"github.com/grokify/govex/severity"
)

func (vs *Vulnerabilities) SeverityStats(slaPolicy severity.SLAPolicy, slaCalcTime time.Time) (*severity.SeverityStats, error) {
	statsSet := severity.NewSeverityStats()
	for _, vn := range *vs {
		if vn.SLATimeStart == nil {
			continue
		} else if vn.SLATimeStart.Before(slaCalcTime) {
			if err := statsSet.Add(slaPolicy, vn.Severity, slaCalcTime.Sub(*vn.SLATimeStart)); err != nil {
				return &statsSet, err
			}
		}
	}
	return &statsSet, nil
}
