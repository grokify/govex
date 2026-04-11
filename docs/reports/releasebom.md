# Release BOM

Generate Release Bill of Materials with vulnerability tracking.

## Installation

```go
import "github.com/grokify/govex/reports/releasebom"
```

## Overview

Release BOM creates manifests that track vulnerabilities across container images and modules in a release. This is useful for:

- Release approval workflows
- Security sign-off documentation
- Compliance tracking
- Container vulnerability summaries

## Usage

### Create Release BOM

```go
bom := releasebom.ReleaseBOM{
    Name:    "my-service",
    Version: "1.2.3",
    Date:    time.Now(),
    Images:  []releasebom.Image{...},
}
```

### From Vulnerability Set

```go
// Map modules to container image names
moduleToImage := map[string]string{
    "backend-api": "myregistry/backend:1.2.3",
    "frontend":    "myregistry/frontend:1.2.3",
}

bom := vulns.ReleaseBOMModuleToImageName(moduleToImage)
```

### Severity Counts by Module

```go
counts := vulns.SeverityCountSetsByModule()
// Returns: map[module]SeverityCounts
```

## Export Formats

### Markdown

```go
md := bom.Markdown()
```

### YAML

```go
yaml := bom.YAML()
```

## BOM Structure

```yaml
name: my-service
version: 1.2.3
date: 2026-04-11
images:
  - name: myregistry/backend:1.2.3
    module: backend-api
    vulnerabilities:
      critical: 0
      high: 2
      medium: 5
      low: 10
  - name: myregistry/frontend:1.2.3
    module: frontend
    vulnerabilities:
      critical: 0
      high: 0
      medium: 3
      low: 8
```

## Related

- [Core Package](../packages/core.md) - Vulnerability types
- [Severity Package](../packages/severity.md) - SeverityCounts type
