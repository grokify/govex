# Site Writer

Generate Markdown websites for vulnerability tracking.

## Installation

```go
import "github.com/grokify/govex/reports/sitewriter"
```

## Overview

Site Writer creates Markdown documentation sites for tracking vulnerabilities across multiple projects. Output is compatible with:

- Git repository viewers (GitHub, GitLab)
- MkDocs
- Other static site generators

## Usage

### Generate Site for Repository

```go
writer := sitewriter.New()

// Write vulnerability pages for a repo
err := vulnSet.WriteFilesSiteForRepo(writer, "my-project")
```

### CLI Usage

```bash
# Generate homepage
govex homepage --output docs/index.md
```

## Site Structure

Generated site structure:

```
docs/
├── index.md              # Homepage with summary
├── projects/
│   ├── project-a/
│   │   ├── index.md      # Project summary
│   │   └── 2024-01/      # Monthly reports
│   │       └── index.md
│   └── project-b/
│       └── ...
└── reports/
    └── ...
```

## Homepage Generation

The homepage aggregates statistics across all projects:

```go
// Generate homepage content
homepage := writer.Homepage(projects)

// Write to file
err := os.WriteFile("docs/index.md", []byte(homepage), 0644)
```

## Merge Command

Combine multiple JSON files for site generation:

```bash
# Merge vulnerability files
govex merge \
  --input project-a.json \
  --input project-b.json \
  --output combined.json

# Then generate site
```

## Integration with MkDocs

The generated Markdown works with MkDocs:

```yaml
# mkdocs.yml
nav:
  - Home: index.md
  - Projects:
    - Project A: projects/project-a/index.md
    - Project B: projects/project-b/index.md
```

## Related

- [CLI merge command](../cli/merge.md)
- [CLI homepage command](../cli/homepage.md)
