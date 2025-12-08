package analyzers

import (
	"fmt"

	"github.com/grokify/govex"
	"github.com/grokify/govex/analyzers/semgrep"
	"github.com/grokify/govex/analyzers/spotbugs"
)

const (
	AnalyzerSemgrep  = semgrep.AnalyzerSemgrep
	AnalyzerSpotBugs = spotbugs.AnalyzerSpotBugs
)

type FileInfo struct {
	Filename string
	Analyzer string
}

type FileInfos []FileInfo

func (infos FileInfos) MergeVulnerabilities(inclSecurityOnly bool) (govex.Vulnerabilities, error) {
	vulns := govex.Vulnerabilities{}
	for _, info := range infos {
		switch info.Analyzer {
		case AnalyzerSemgrep:
			if out, err := semgrep.ParseJSONFromFile(info.Filename); err != nil {
				return nil, err
			} else if vs, err := out.ToGovexVulnerabilities(); err != nil {
				return nil, err
			} else {
				vulns = append(vulns, vs...)
			}
		case AnalyzerSpotBugs:
			if rpt, err := spotbugs.ParseBugCollectionFromFile(info.Filename); err != nil {
				return nil, err
			} else if vs, err := rpt.ToGovexVulnerabilities(inclSecurityOnly); err != nil {
				return nil, err
			} else {
				vulns = append(vulns, vs...)
			}
		default:
			return nil, fmt.Errorf("filetype unknown (%s)", info.Analyzer)
		}
	}
	return vulns, nil
}
