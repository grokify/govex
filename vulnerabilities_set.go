package govex

import (
	"os"

	"github.com/grokify/mogo/encoding/jsonutil"
)

type VulnerabilitiesSet struct {
	Vulnerabilities Vulnerabilities `json:"vulnerabilities"`
}

func NewVulnerabilitiesSet() VulnerabilitiesSet {
	return VulnerabilitiesSet{
		Vulnerabilities: Vulnerabilities{},
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
