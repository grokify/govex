package nvd

import (
	"encoding/json"
	"time"
)

const iso8601Millis = "2006-01-02T15:04:05.000"

// CVEHistoryResponse represents the root structure of the NVD CVE History API response
type CVEHistoryResponse struct {
	ResultsPerPage int         `json:"resultsPerPage"`
	StartIndex     int         `json:"startIndex"`
	TotalResults   int         `json:"totalResults"`
	Format         string      `json:"format"`
	Version        string      `json:"version"`
	Timestamp      time.Time   `json:"timestamp"`
	CVEChanges     []CVEChange `json:"cveChanges"`
}

// CVEChange represents a single CVE change entry
type CVEChange struct {
	Change Change `json:"change"`
}

// Change represents the details of a CVE change
type Change struct {
	CVEID            string    `json:"cveId"`
	EventName        string    `json:"eventName"`
	CVEChangeID      string    `json:"cveChangeId"`
	SourceIdentifier string    `json:"sourceIdentifier"`
	Created          time.Time `json:"created"`
	Details          []Detail  `json:"details"`
}

// Detail represents a specific change detail within a CVE change
type Detail struct {
	Action   string `json:"action"`
	Type     string `json:"type"`
	NewValue string `json:"newValue"`
}

func (c *CVEHistoryResponse) UnmarshalJSON(data []byte) error {
	type Alias CVEHistoryResponse
	aux := &struct {
		Timestamp string `json:"timestamp"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.Timestamp != "" {
		t, err := time.Parse(iso8601Millis, aux.Timestamp)
		if err != nil {
			return err
		}
		c.Timestamp = t
	}
	return nil
}

func (c *Change) UnmarshalJSON(data []byte) error {
	type Alias Change
	aux := &struct {
		Created string `json:"created"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.Created != "" {
		t, err := time.Parse(iso8601Millis, aux.Created)
		if err != nil {
			return err
		}
		c.Created = t
	}
	return nil
}
