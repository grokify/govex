# CISA KEV Integration

Integration with [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Installation

```go
import "github.com/grokify/govex/feeds/cisakev"
```

## Overview

The CISA KEV catalog lists vulnerabilities that are actively being exploited in the wild. This integration allows you to:

- Download the KEV catalog
- Check if your vulnerabilities appear in KEV
- Prioritize remediation based on active exploitation

## Usage

### Load KEV Catalog

```go
// Load from CISA feed
kev, err := cisakev.LoadFromURL()
if err != nil {
    log.Fatal(err)
}

// Or load from local file
kev, err := cisakev.LoadFromFile("kev.json")
```

### Check for Known Exploited CVEs

```go
// Check if a CVE is in KEV
isExploited := kev.Contains("CVE-2024-1234")

// Get KEV entry details
entry, found := kev.Get("CVE-2024-1234")
if found {
    fmt.Println("Due date:", entry.DueDate)
    fmt.Println("Vendor:", entry.VendorProject)
}
```

### Filter Vulnerabilities by KEV Status

```go
// Get vulnerabilities that are in KEV
exploited := vulns.FilterByKEV(kev)

// Prioritize KEV vulnerabilities
for _, v := range exploited {
    fmt.Printf("URGENT: %s is actively exploited\n", v.ID)
}
```

### Convert to GoVEX Format

```go
// Convert entire KEV catalog to vulnerabilities
vulns := kev.ToVulnerabilities()

// Generate report
table := vulns.Table(govex.TableColumnDefinitionSetSASTSCAReport())
```

## KEV Entry Fields

| Field | Description |
|-------|-------------|
| `cveID` | CVE identifier |
| `vendorProject` | Affected vendor/project |
| `product` | Affected product |
| `vulnerabilityName` | Description of the vulnerability |
| `dateAdded` | When added to KEV |
| `dueDate` | CISA remediation due date |
| `knownRansomwareCampaignUse` | Used in ransomware campaigns |

## CISA Feed URL

The catalog is available at:

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

## Use Cases

### Prioritization Report

```go
// Load your vulnerabilities
vulns, _ := govex.ReadVulnerabilitiesFile("scan-results.json")

// Load KEV
kev, _ := cisakev.LoadFromURL()

// Split by KEV status
inKEV := vulns.FilterByKEV(kev)
notInKEV := vulns.FilterNotInKEV(kev)

fmt.Printf("Actively exploited: %d\n", len(inKEV))
fmt.Printf("Not in KEV: %d\n", len(notInKEV))
```

### CI/CD Gate

```go
// Fail build if any KEV vulnerabilities found
if len(inKEV) > 0 {
    for _, v := range inKEV {
        log.Printf("CRITICAL: %s is actively exploited", v.ID)
    }
    os.Exit(1)
}
```

## Related

- [Integrations Overview](index.md)
- [NVD Reference](../standards/cve.md)
