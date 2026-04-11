# CVE 2.0 Support

Support for the NIST CVE 2.0 JSON format.

## Installation

```go
import "github.com/grokify/govex/standards/cve20"
```

## Overview

CVE (Common Vulnerabilities and Exposures) is the standard identifier for security vulnerabilities. GoVEX supports parsing CVE 2.0 JSON format used by NVD and other sources.

## Usage

### Parse CVE JSON

```go
cve, err := cve20.ParseFile("CVE-2024-1234.json")
if err != nil {
    log.Fatal(err)
}

fmt.Println("CVE ID:", cve.ID)
fmt.Println("Description:", cve.Description)
```

### Convert to GoVEX

```go
vuln := cve.ToVulnerability()
```

## CVE Fields

| Field | Description |
|-------|-------------|
| `cveId` | CVE identifier (e.g., CVE-2024-1234) |
| `descriptions` | Multi-language descriptions |
| `metrics` | CVSS scores |
| `weaknesses` | CWE mappings |
| `references` | External references |
| `affected` | Affected products |

## NVD API Client

Query the NVD directly:

```go
import "github.com/grokify/govex/nvd"

client := nvd.NewClient(apiKey)

// Get single CVE
cve, err := client.GetCVE("CVE-2024-1234")

// Search CVEs
results, err := client.SearchCVEs(nvd.SearchParams{
    KeywordSearch: "apache",
    PubStartDate:  "2024-01-01",
})
```

## Related

- [CVSS Support](cvss.md)
- [CWE Support](cwe.md)
- [CISA KEV](../integrations/cisakev.md)
