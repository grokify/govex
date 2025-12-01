package govex

import (
	"time"

	"github.com/grokify/gocharts/v2/data/histogram"
	"github.com/grokify/mogo/type/maputil"

	"github.com/grokify/govex/severity"
)

func (vs *Vulnerabilities) SeverityCounts() maputil.Records {
	h := vs.SeverityHistogram()
	return h.ItemValuesOrdered()
}

func (vs *Vulnerabilities) SeverityCountsString(sep string) string {
	recs := vs.SeverityCounts()
	return recs.String(sep)
}

func (vs *Vulnerabilities) SeverityHistogram() histogram.Histogram {
	h := histogram.NewHistogram("")
	h.Order = severity.SeveritiesAll()
	for _, vn := range *vs {
		h.Add(vn.Severity, 1)
	}
	h.Order = severity.SeveritiesAll()
	return *h
}

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

func (vs *Vulnerabilities) SeverityStatsSetByModule(slaPolicy severity.SLAPolicy, slaCalcTime time.Time, unknownModule string) (severity.SeverityStatsSet, error) {
	statsSet := severity.NewSeverityStatsSet()
	for _, vn := range *vs {
		if vn.SLATimeStart == nil {
			continue
		} else if vn.SLATimeStart.Before(slaCalcTime) {
			if err := statsSet.Add(slaPolicy, vn.Module, vn.Severity, slaCalcTime.Sub(*vn.SLATimeStart)); err != nil {
				return statsSet, err
			}
		}
	}
	return statsSet, nil
}

func (vs *Vulnerabilities) SeverityStatsSetBySeverity(slaPolicy severity.SLAPolicy, slaCalcTime time.Time, unknownModule string) (severity.SeverityStatsSet, error) {
	statsSet := severity.NewSeverityStatsSet()
	statsSet.Order = []string{
		severity.SeverityCritical,
		severity.SeverityHigh,
		severity.SeverityMedium,
		severity.SeverityLow}
	for _, vn := range *vs {
		if vn.SLATimeStart == nil {
			continue
		} else if vn.SLATimeStart.Before(slaCalcTime) {
			if err := statsSet.Add(slaPolicy, vn.Severity, vn.Severity, slaCalcTime.Sub(*vn.SLATimeStart)); err != nil {
				return statsSet, err
			}
		}
	}
	return statsSet, nil
}
