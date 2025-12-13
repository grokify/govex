package cve20

import (
	"encoding/json"
	"io"
	"os"

	"github.com/grokify/mogo/encoding/jsonutil"
)

const (
	FormatNVDCVE          = "NVD_CVE"
	FormatNVDCVEVersion20 = "2.0"
)

type CVEAPIResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Vulnerabilities Vulnerabilities `json:"vulnerabilities"`
}

func (r CVEAPIResponse) WriteFileJSON(filename, indent, prefix string, perm os.FileMode) error {
	if b, err := jsonutil.MarshalSimple(r, prefix, indent); err != nil {
		return err
	} else {
		return os.WriteFile(filename, b, perm)
	}
}

type Vulnerabilities []Vulnerability

type Vulnerability struct {
	CVE *CVE `json:"cve,omitempty"`
	SVE *CVE `json:"sve,omitempty"`
}

func (r *CVEAPIResponse) Inflate() {
	r.Format = FormatNVDCVE
	r.Version = FormatNVDCVEVersion20
	r.ResultsPerPage = len(r.Vulnerabilities)
	r.TotalResults = len(r.Vulnerabilities)
}

func ParseCVEAPIResponseFile(filename string) (*CVEAPIResponse, []byte, error) {
	if b, err := os.ReadFile(filename); err != nil {
		return nil, b, err
	} else {
		res := &CVEAPIResponse{}
		return res, b, json.Unmarshal(b, res)
	}
}

func ParseCVEAPIResponseReader(r io.Reader) (*CVEAPIResponse, []byte, error) {
	var res *CVEAPIResponse
	b, err := jsonutil.UnmarshalReader(r, res)
	return res, b, err
}
