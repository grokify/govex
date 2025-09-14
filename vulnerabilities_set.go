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
	VulnValueOpts   *ValueOptions   `json:"vulnValueOpts"`
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
			if strings.TrimSpace(iset.Name) != "" {
				set.Name = iset.Name
			}
			if strings.TrimSpace(iset.RepoPath) != "" {
				set.RepoPath = iset.RepoPath
			}
			if strings.TrimSpace(iset.RepoURL) != "" {
				set.RepoURL = iset.RepoURL
				if set.RepoPath == "" {
					set.SetRepoURL(iset.RepoURL)
				}
			}
			if iset.DateTime != nil && !iset.DateTime.IsZero() {
				set.DateTime = iset.DateTime
			}
			set.Vulnerabilities = append(set.Vulnerabilities, iset.Vulnerabilities...)
		}
	}
	return &set, nil
}

func (vs *VulnerabilitiesSet) SetRepoURL(s string) {
	vs.RepoURL = strings.TrimSuffix(s, ".git")
	if strings.TrimSpace(vs.RepoPath) == "" {
		rp := vs.RepoURL
		rp = strings.TrimPrefix(rp, "git://")
		vs.RepoPath = strings.TrimPrefix(rp, "https://")
	}
}

func (vs *VulnerabilitiesSet) SeverityStatusSetsByCategory(slaRefTime time.Time) (*SeverityStatusSets, error) {
	out := NewSeverityStatusSets()
	if vs.VulnValueOpts != nil && vs.VulnValueOpts.SLAOptions != nil {
		out.SLAMap = vs.VulnValueOpts.SLAOptions.SLAMap
	}
	for _, v := range vs.Vulnerabilities {
		ageDur := v.Age(slaRefTime, 0)
		if err := out.Add(v.Category, v.Severity, ageDur); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (vs *VulnerabilitiesSet) SeverityStatusSetsByTag(slaRefTime time.Time) (*SeverityStatusSets, error) {
	out := NewSeverityStatusSets()
	if vs.VulnValueOpts != nil && vs.VulnValueOpts.SLAOptions != nil {
		out.SLAMap = vs.VulnValueOpts.SLAOptions.SLAMap
	}
	for _, v := range vs.Vulnerabilities {
		ageDur := v.Age(slaRefTime, 0)
		for _, tag := range v.Tags {
			if err := out.Add(tag, v.Severity, ageDur); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func (vs *VulnerabilitiesSet) WriteFileJSON(filename string, prefix, indent string, perm os.FileMode) error {
	return jsonutil.MarshalFile(filename, vs, prefix, indent, perm)
}
