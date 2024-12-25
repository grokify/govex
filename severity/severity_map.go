package severity

import (
	"errors"

	"github.com/shopspring/decimal"
)

type SeverityMap map[string]decimal.Decimal

func NewSeverityMapFromFloat32(m map[string]float32) (SeverityMap, error) {
	sm := SeverityMap{}
	for k, v := range m {
		sev, err := ParseSeverity(k)
		if err != nil {
			return sm, err
		} else {
			sm[sev] = decimal.NewFromFloat32(v)
		}
	}
	return sm, nil
}

func NewSeverityMapSeveritiesOnly(severities []string) (SeverityMap, error) {
	sm := SeverityMap{}
	for _, k := range severities {
		if sev, err := ParseSeverity(k); err != nil {
			return sm, err
		} else {
			sm[sev] = decimal.NewFromInt(0)
		}
	}
	return sm, nil
}

func SeverityMapScoreDefault() map[string]decimal.Decimal {
	return map[string]decimal.Decimal{
		SeverityCritical:      decimal.NewFromInt(9),
		SeverityHigh:          decimal.NewFromInt(7),
		SeverityMedium:        decimal.NewFromInt(4),
		SeverityLow:           decimal.NewFromFloat32(0.1),
		SeverityInformational: decimal.NewFromInt(0)}
}

func (sm SeverityMap) SeverityFromScoreFloat32(score float32) (string, error) {
	return sm.SeverityFromScore(decimal.NewFromFloat32(score))
}

func (sm SeverityMap) SeverityFromScore(score decimal.Decimal) (string, error) {
	d10 := decimal.NewFromInt(10)
	d0 := decimal.NewFromInt(0)
	if score.Cmp(d10) > 0 || score.Cmp(d0) < 0 {
		return SeverityUnknown, errors.New("score out of range")
	}
	sevs := SeveritiesAll()
	for _, sev := range sevs {
		if min, ok := sm[sev]; ok {
			if score.Cmp(min) >= 0 {
				return sev, nil
			}
		}
	}
	return SeverityUnknown, errors.New("not classified")
}
