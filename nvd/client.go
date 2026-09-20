package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/grokify/mogo/net/http/httpsimple"
)

const (
	NVDAPIURLCVEHistory20           = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
	nvdAPIURLCVEHistory20ParamCVEID = "cveId"
)

type Client struct {
	client *http.Client
}

func (c Client) GetCVEHitory(ctx context.Context, cveID string) (*CVEHistoryResponse, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, errors.New("cveID cannot be empty")
	}
	sr := httpsimple.Request{
		Method: http.MethodGet,
		URL:    NVDAPIURLCVEHistory20,
		Query: map[string][]string{
			nvdAPIURLCVEHistory20ParamCVEID: {cveID}},
	}
	if resp, err := sr.Do(ctx, c.client); err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("invalid status code (%d)", resp.StatusCode)
	} else if b, err := io.ReadAll(resp.Body); err != nil {
		return nil, err
	} else {
		fmt.Println(string(b))
		cveHist := &CVEHistoryResponse{}
		return cveHist, json.Unmarshal(b, cveHist)
	}
}
