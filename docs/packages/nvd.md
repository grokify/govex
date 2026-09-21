# NVD Package

The `nvd` package provides a client for the NIST National Vulnerability Database (NVD) CVE History API (version 2.0). It fetches the change history for a given CVE and unmarshals NVD's millisecond-precision ISO-8601 timestamps into Go `time.Time` values.

## Installation

```go
import "github.com/grokify/govex/nvd"
```

## Client

`Client` wraps an optional `*http.Client` and issues requests against the NVD CVE History endpoint:

| Symbol | Notes |
|--------|-------|
| `Client` | Struct holding an unexported `*http.Client`; the zero value works and uses the default HTTP client |
| `Client.GetCVEHitory(ctx, cveID)` | Fetches change history for `cveID` (note the method name spelling as in source); returns `(*CVEHistoryResponse, error)` |
| `NVDAPIURLCVEHistory20` | Endpoint constant: `https://services.nvd.nist.gov/rest/json/cvehistory/2.0` |

`GetCVEHitory` trims and upper-cases the supplied CVE ID, returns an error if it is empty, sends it as the `cveId` query parameter, and treats any HTTP status code of 300 or greater as an error.

```go
clt := nvd.Client{}

resp, err := clt.GetCVEHitory(context.Background(), "CVE-2025-6000")
if err != nil {
    log.Fatal(err)
}

for _, cveChange := range resp.CVEChanges {
    fmt.Println(cveChange.Change.EventName, cveChange.Change.Created)
}
```

## Response Types

The API response is modeled by four types:

| Type | Description |
|------|-------------|
| `CVEHistoryResponse` | Root response: paging fields plus a slice of `CVEChange` |
| `CVEChange` | Wraps a single `Change` entry |
| `Change` | Details of one change event (CVE ID, event name, source, timestamp, details) |
| `Detail` | A specific field-level change within a `Change` |

### CVEHistoryResponse

```go
type CVEHistoryResponse struct {
    ResultsPerPage int         `json:"resultsPerPage"`
    StartIndex     int         `json:"startIndex"`
    TotalResults   int         `json:"totalResults"`
    Format         string      `json:"format"`
    Version        string      `json:"version"`
    Timestamp      time.Time   `json:"timestamp"`
    CVEChanges     []CVEChange `json:"cveChanges"`
}
```

### CVEChange, Change, and Detail

```go
type CVEChange struct {
    Change Change `json:"change"`
}

type Change struct {
    CVEID            string    `json:"cveId"`
    EventName        string    `json:"eventName"`
    CVEChangeID      string    `json:"cveChangeId"`
    SourceIdentifier string    `json:"sourceIdentifier"`
    Created          time.Time `json:"created"`
    Details          []Detail  `json:"details"`
}

type Detail struct {
    Action   string `json:"action"`
    Type     string `json:"type"`
    NewValue string `json:"newValue"`
}
```

## Timestamp Handling

NVD serializes `timestamp` and `created` as ISO-8601 strings with millisecond precision and no timezone offset (for example `2025-01-02T15:04:05.000`), which Go's default `time.Time` unmarshaling cannot parse. `CVEHistoryResponse` and `Change` therefore implement custom `UnmarshalJSON` methods that decode those fields as strings and parse them with the `2006-01-02T15:04:05.000` layout, leaving the value zero when the field is absent. Callers receive fully populated `time.Time` values with no extra handling.

## CLI

The `nvd/cmd/getcvehist` command fetches and prints the change history for a CVE. It constructs a `Client`, calls `GetCVEHitory`, and prints the response as JSON:

```bash
go run ./nvd/cmd/getcvehist
```

## Related

- [CVE Package](cve.md) - Extract CVE IDs from arbitrary text
- [CVE 2.0 Support](../standards/cve.md) - Parse the NVD CVE 2.0 record format
