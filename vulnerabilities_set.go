package govex

import (
	"os"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/mogo/encoding/jsonutil"
)

type VulnerabilitiesSet struct {
	Vulnerabilities Vulnerabilities `json:"vulnerabilities"`
}

func (vs *VulnerabilitiesSet) WriteFileXLSX(filename, sheetname string, colDefs table.ColumnDefinitionSet, opts *ValueOpts) error {
	if tbl, err := vs.Vulnerabilities.Table(colDefs, opts); err != nil {
		return err
	} else {
		return tbl.WriteXLSX(filename, sheetname)
	}
}

func (vs *VulnerabilitiesSet) WriteFileJSON(filename string, prefix, indent string, perm os.FileMode) error {
	return jsonutil.MarshalFile(filename, vs, prefix, indent, perm)
}

func ReadFileVulnerabilitiesSet(filename string) (*VulnerabilitiesSet, error) {
	set := VulnerabilitiesSet{}
	return &set, jsonutil.UnmarshalFile(filename, &set)
}

func ReadFilesVulnerabilitiesSet(filenames []string) (*VulnerabilitiesSet, error) {
	set := VulnerabilitiesSet{}
	for _, filename := range filenames {
		if si, err := ReadFileVulnerabilitiesSet(filename); err != nil {
			return nil, err
		} else if len(si.Vulnerabilities) > 0 {
			set.Vulnerabilities = append(set.Vulnerabilities, si.Vulnerabilities...)
		}
	}
	return &set, nil
}
