# CVE Package

The `cve` package extracts CVE identifiers from arbitrary text. It is a small text-parsing helper: given any string, it returns the CVE IDs it contains. For parsing the structured NVD CVE 2.0 record format, see [CVE 2.0 Support](../standards/cve.md) instead.

## Installation

```go
import "github.com/grokify/govex/cve"
```

## API

| Symbol | Description |
|--------|-------------|
| `ParseCVEIDs(s string) []string` | Extracts every CVE ID from `s` using a case-insensitive regex and returns them sorted |
| `RawData` | Package-level string holding a sample of public CVE IDs and related fields, useful for examples and testing |

`ParseCVEIDs` matches CVE IDs with the case-insensitive pattern `\bcve\-[0-9]+\-[0-9]+`, so identifiers embedded in surrounding text (for example `videoconversion@CVE-2022-49168`) are still extracted. The returned slice is sorted with `sort.Strings`.

```go
ids := cve.ParseCVEIDs("videoconversion@CVE-2022-49168, see also cve-2025-21796")
// []string{"CVE-2022-49168", "cve-2025-21796"}

sample := cve.ParseCVEIDs(cve.RawData)
fmt.Printf("found %d CVE IDs\n", len(sample))
```

Because the match is case-insensitive, IDs are returned with whatever casing they appear in the input; normalize to upper case if you need canonical form.

## CLI

The `cve/cmd/parse` command demonstrates the package: it calls `ParseCVEIDs` on the embedded `RawData` sample and on a second POA&M-style list, prints both sets as JSON with counts, and computes their set intersection.

```bash
go run ./cve/cmd/parse
```

## Related

- [CVE 2.0 Support](../standards/cve.md) - Parse the structured NVD CVE 2.0 record format
- [NVD Package](nvd.md) - Fetch CVE change history from the NVD API
