package govex

import (
	"os"
	"strings"
	"time"

	"github.com/grokify/mogo/encoding/jsonutil"
)

type VulnerabilitiesSet struct {
	Name            string          `json:"name"`
	RepoPath        string          `json:"repoPath"`
	RepoURL         string          `json:"repoURL"`
	DateTime        *time.Time      `json:"dateTime"`
	VulnValueOpts   *ValueOpts      `json:"vulnValueOpts"`
	Vulnerabilities Vulnerabilities `json:"vulnerabilities"`
}

func NewVulnerabilitiesSet() *VulnerabilitiesSet {
	return &VulnerabilitiesSet{
		Vulnerabilities: Vulnerabilities{},
	}
}

func ReadFilesVulnerabilitiesSet(filenames ...string) (*VulnerabilitiesSet, error) {
	set := VulnerabilitiesSet{}
	for _, filename := range filenames {
		iset := VulnerabilitiesSet{}
		if err := jsonutil.UnmarshalFile(filename, &iset); err != nil {
			return nil, err
		} else if len(iset.Vulnerabilities) > 0 {
			set.Vulnerabilities = append(set.Vulnerabilities, iset.Vulnerabilities...)
		}
	}
	return &set, nil
}

func (vs *VulnerabilitiesSet) RepoPathFile() string {
	rp := vs.RepoPath
	rp = strings.TrimPrefix(rp, "git://")
	rp = strings.TrimPrefix(rp, "https://")
	return strings.TrimSuffix(vs.RepoPath, "/.git")
}

func (vs *VulnerabilitiesSet) WriteFileJSON(filename string, prefix, indent string, perm os.FileMode) error {
	return jsonutil.MarshalFile(filename, vs, prefix, indent, perm)
}
