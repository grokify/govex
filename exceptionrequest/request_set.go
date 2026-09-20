package exceptionrequest

import "sort"

type RequestSet struct {
	IDs        []string
	Approved   Requests
	InProgress Requests
}

func NewRequestSet() *RequestSet {
	return &RequestSet{
		IDs:        []string{},
		Approved:   Requests{},
		InProgress: Requests{},
	}
}

type StatusStats struct {
	IDsFiledClosed         []string
	IDsFiledApproved       []string
	IDsFiledInProgress     []string
	IDsFiledAll            []string
	IDsFiledNotCategorized []string // IdsAll
}

func (set RequestSet) Status() StatusStats {
	stats := StatusStats{}
	ids := set.IDs
	sort.Strings(ids)
	idsMapApproved := set.Approved.IDsMap()
	idsMapInProgress := set.InProgress.IDsMap()
	for _, id := range ids {
		stats.IDsFiledAll = append(stats.IDsFiledAll, id)
		req, err := set.InProgress.Request(id)
		if err == nil {
			if req.IsClosed {
				stats.IDsFiledClosed = append(stats.IDsFiledClosed, id)
				continue
			}
		}
		isApproved := false
		inProgress := false
		if _, ok := idsMapApproved[id]; ok {
			stats.IDsFiledApproved = append(stats.IDsFiledApproved, id)
			isApproved = true
		}
		if _, ok := idsMapInProgress[id]; ok {
			stats.IDsFiledInProgress = append(stats.IDsFiledInProgress, id)
			inProgress = true
		}
		if !isApproved && !inProgress {
			stats.IDsFiledNotCategorized = append(stats.IDsFiledNotCategorized, id)
		}
	}
	return stats
}
