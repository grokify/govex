package govex

import (
	"time"

	"github.com/grokify/mogo/type/maputil"

	"github.com/grokify/govex/severity"
)

type VulnerabilitiesSets struct {
	Items map[string]VulnerabilitiesSet
}

func NewVulnerabilitiesSets() *VulnerabilitiesSets {
	return &VulnerabilitiesSets{
		Items: map[string]VulnerabilitiesSet{},
	}
}

func (sets *VulnerabilitiesSets) Add(setName string, vn Vulnerability) {
	set, ok := sets.Items[setName]
	if !ok {
		set = *NewVulnerabilitiesSet()
	}
	set.Vulnerabilities = append(set.Vulnerabilities, vn)
	sets.Items[setName] = set
}

func (sets *VulnerabilitiesSets) ItemNames() []string {
	return maputil.Keys(sets.Items)
}

func (sets *VulnerabilitiesSets) SeverityStatsSetBySetName(slaPolicy severity.SLAPolicy, slaCalcTime time.Time, unknownSetName string) (severity.SeverityStatsSet, error) {
	statsSet := severity.NewSeverityStatsSet()
	names := sets.ItemNames()
	for _, setName := range names {
		vs := sets.Items[setName]
		stats, err := vs.Vulnerabilities.SeverityStats(slaPolicy, slaCalcTime)
		if err != nil {
			return statsSet, err
		} else {
			statsSet.Items[setName] = *stats
		}
	}
	return statsSet, nil
}
