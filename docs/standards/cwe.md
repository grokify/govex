# CWE Support

Support for Common Weakness Enumeration (CWE).

## Installation

```go
import "github.com/grokify/govex/standards/cwe"
```

## Overview

CWE is a community-developed list of software and hardware weakness types. GoVEX supports parsing CWE identifiers and XML data.

## Usage

### Parse CWE ID

```go
// Parse CWE identifier
id, err := cwe.ParseCWEAsPrefix("CWE-79")
if err != nil {
    log.Fatal(err)
}
fmt.Println("CWE Number:", id) // 79
```

### Parse Multiple CWEs

```go
// Parse multiple CWE identifiers
ids := cwe.ParseCWEsAsPrefix([]string{"CWE-79", "CWE-89", "CWE-22"})
```

## Common CWEs

| CWE | Name | Category |
|-----|------|----------|
| CWE-79 | Cross-site Scripting (XSS) | Injection |
| CWE-89 | SQL Injection | Injection |
| CWE-22 | Path Traversal | Input Validation |
| CWE-78 | OS Command Injection | Injection |
| CWE-352 | Cross-Site Request Forgery | Session Management |
| CWE-287 | Improper Authentication | Authentication |
| CWE-862 | Missing Authorization | Authorization |
| CWE-798 | Hard-coded Credentials | Credentials |
| CWE-200 | Information Exposure | Information Leak |
| CWE-502 | Deserialization | Input Validation |

## OWASP Top 10 Mapping

| OWASP 2021 | Related CWEs |
|------------|--------------|
| A01 Broken Access Control | CWE-200, CWE-284, CWE-862 |
| A02 Cryptographic Failures | CWE-259, CWE-327, CWE-331 |
| A03 Injection | CWE-79, CWE-89, CWE-78 |
| A04 Insecure Design | CWE-209, CWE-256, CWE-501 |
| A05 Security Misconfiguration | CWE-16, CWE-611, CWE-1004 |
| A06 Vulnerable Components | CWE-937 |
| A07 Auth Failures | CWE-287, CWE-384, CWE-613 |
| A08 Integrity Failures | CWE-494, CWE-502, CWE-829 |
| A09 Logging Failures | CWE-117, CWE-223, CWE-532 |
| A10 SSRF | CWE-918 |

## Related

- [CVE Support](cve.md)
- [Semgrep Integration](../integrations/semgrep.md) - CWE mapping from SAST
