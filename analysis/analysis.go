package analysis

import (
	"errors"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/gocharts/v2/data/table/sheet"
)

type Analysis struct {
	State         ImpactAnalysisState
	Justification string
	Evidence      string
}

type AnalysisSet struct {
	Data map[string]Analysis
}

func NewAnalysisSet() AnalysisSet {
	return AnalysisSet{
		Data: map[string]Analysis{},
	}
}

func (set *AnalysisSet) ReadTable(t *table.Table, attrToLettersMap map[string]string) error {
	if t == nil {
		return errors.New("table cannot be nil")
	}
	colIdxEvidence := -1
	colIdxJustification := -1
	colIdxState := -1
	for k, v := range attrToLettersMap {
		colNum, err := sheet.ColLettersToNumber(v)
		if err != nil {
			return err
		}
		colIdx := colNum - 1
		switch k {
		case FieldEvidence:
			colIdxEvidence = int(colIdx)
		case FieldJustification:
			colIdxJustification = int(colIdx)
		case FieldState:
			colIdxState = int(colIdx)
		}
	}
	if colIdxEvidence < 0 && colIdxJustification < 0 && colIdxState < 0 {
		return errors.New("no columns recognized")
	}
	for _, row := range t.Rows {
		a := Analysis{}
		if colIdxEvidence >= 0 && colIdxEvidence < len(row) {
			a.Evidence = row[colIdxEvidence]
		}
		if colIdxJustification >= 0 && colIdxJustification < len(row) {
			a.Justification = row[colIdxJustification]
		}
		if colIdxState >= 0 && colIdxState < len(row) {
			state, err := ParseImpactAnalysisState(row[colIdxState], IASNotStarted)
			if err != nil {
				return err
			}
			a.State = state
		}
	}
	return nil
}
