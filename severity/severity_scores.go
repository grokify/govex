package severity

import (
	"errors"

	"github.com/shopspring/decimal"
)

type SeverityMapCVSS map[string]decimal.Decimal

func NewSeverityMapFromFloat32(m map[string]float32) (SeverityMapCVSS, error) {
	sm := SeverityMapCVSS{}
	for k, v := range m {
		sev, _, err := ParseSeverity(k)
		if err != nil {
			return sm, err
		} else {
			sm[sev] = decimal.NewFromFloat32(v)
		}
	}
	return sm, nil
}

func NewSeverityMapCVSSSeveritiesOnly(severities []string) (SeverityMapCVSS, error) {
	sm := SeverityMapCVSS{}
	for _, k := range severities {
		if sev, _, err := ParseSeverity(k); err != nil {
			return sm, err
		} else {
			sm[sev] = decimal.NewFromInt(0)
		}
	}
	return sm, nil
}

func SeverityMapScoreDefault() SeverityMapCVSS {
	return map[string]decimal.Decimal{
		SeverityCritical:      decimal.NewFromInt(9),
		SeverityHigh:          decimal.NewFromInt(7),
		SeverityMedium:        decimal.NewFromInt(4),
		SeverityLow:           decimal.NewFromFloat32(0.1),
		SeverityInformational: decimal.NewFromInt(0)}
}

func (sm SeverityMapCVSS) SeverityFromScoreFloat32(score float32) (string, error) {
	return sm.SeverityFromScore(decimal.NewFromFloat32(score))
}

func (sm SeverityMapCVSS) SeverityFromScore(score decimal.Decimal) (string, error) {
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
