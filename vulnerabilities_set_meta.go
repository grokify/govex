package govex

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

type VulnerabilitiesSetMeta struct {
	Name           string         `json:"name"`
	RepoPath       string         `json:"repoPath"`
	RepoURL        string         `json:"repoURL"`
	DateTime       *time.Time     `json:"dateTime"`
	SeverityCounts map[string]int `json:"severityCounts"`
}

func ReadFileVulnerabilitiesSetMeta(filename string) (VulnerabilitiesSetMeta, error) {
	meta := VulnerabilitiesSetMeta{}
	if b, err := os.ReadFile(filename); err != nil {
		return meta, err
	} else if err := json.Unmarshal(b, &meta); err != nil {
		return meta, err
	} else {
		return meta, nil
	}
}

func (meta VulnerabilitiesSetMeta) MissingFields() []string {
	var fields []string
	if strings.TrimSpace(meta.Name) == "" {
		fields = append(fields, "name")
	}
	if strings.TrimSpace(meta.RepoPath) == "" {
		fields = append(fields, "repoPath")
	}
	if strings.TrimSpace(meta.RepoURL) == "" {
		fields = append(fields, "repoURL")
	}
	if meta.DateTime == nil || meta.DateTime.IsZero() {
		fields = append(fields, "dateTime")
	}
	return fields
}

func (meta VulnerabilitiesSetMeta) WriteFile(filename string, perm os.FileMode) error {
	if b, err := json.Marshal(meta); err != nil {
		return err
	} else if err := os.WriteFile(filename, b, perm); err != nil {
		return err
	} else {
		return nil
	}
}

func (vs *VulnerabilitiesSet) WriteFileMeta(filename string, perm os.FileMode) error {
	m := vs.Meta()
	return m.WriteFile(filename, perm)
}

func (vs *VulnerabilitiesSet) Meta() VulnerabilitiesSetMeta {
	meta := VulnerabilitiesSetMeta{
		Name:     vs.Name,
		RepoPath: vs.RepoPath,
		RepoURL:  vs.RepoURL,
		DateTime: vs.DateTime,
	}
	sCounts := vs.Vulnerabilities.SeverityHistogram()
	meta.SeverityCounts = sCounts.Bins
	return meta
}
