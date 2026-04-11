# CSAF Support

Support for Common Security Advisory Framework (CSAF).

## Installation

```go
import "github.com/grokify/govex/standards/csaf"
```

## Overview

CSAF is an OASIS standard for machine-readable security advisories. It's the successor to CVRF (Common Vulnerability Reporting Framework) and is widely used by vendors for publishing security bulletins.

## When to Use CSAF

CSAF is best for:

- Publishing security advisories to customers
- Vendor CVE disclosure
- Security bulletin automation
- Threat intelligence feeds

For internal vulnerability triage, consider CycloneDX + VEX instead. See [Vulnerability Formats](../reference/vulnerability-formats.md) for comparison.

## Usage

### Parse CSAF Document

```go
advisory, err := csaf.ParseFile("advisory.json")
if err != nil {
    log.Fatal(err)
}

fmt.Println("Title:", advisory.Document.Title)
fmt.Println("Publisher:", advisory.Document.Publisher.Name)
```

### Convert to GoVEX

```go
vulns := advisory.ToVulnerabilities()
```

## CSAF Document Structure

```json
{
  "document": {
    "title": "Security Advisory",
    "publisher": {
      "name": "Vendor Name",
      "category": "vendor"
    },
    "tracking": {
      "id": "VENDOR-2024-001",
      "status": "final",
      "version": "1.0"
    }
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2024-1234",
      "title": "Buffer Overflow",
      "scores": [
        {
          "cvss_v3": {
            "baseScore": 9.8,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        }
      ]
    }
  ],
  "product_tree": {
    "branches": [...]
  }
}
```

## CSAF Feeds

Major vendors publishing CSAF feeds:

| Vendor | Feed URL |
|--------|----------|
| Red Hat | `https://access.redhat.com/security/data/csaf/v2/advisories/` |
| Cisco | `https://sec.cloudapps.cisco.com/security-pack/csa` |
| Siemens | `https://www.siemens.com/cert/advisories/csaf` |

## Profiles

CSAF defines several profiles:

| Profile | Use Case |
|---------|----------|
| Informational | General security information |
| Security Incident Response | Incident details |
| Security Advisory | Vulnerability advisories |
| VEX | Exploitability statements |

## Related

- [Vulnerability Formats](../reference/vulnerability-formats.md) - Format comparison
- [CVE Support](cve.md)
- [Standards Overview](index.md)
