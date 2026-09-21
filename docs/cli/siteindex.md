# siteindex

Generate the home index page for a GoVEX report site.

## Overview

`cmd/siteindex` is a standalone utility that writes the home (root) index page for a report site. It delegates to the `sitewriter` package's `CmdSiteWriteHomeRun`, which parses command-line flags and writes the home file.

## Usage

```bash
go run github.com/grokify/govex/cmd/siteindex [flags]
```

Or from a checkout of the repository:

```bash
go run ./cmd/siteindex [flags]
```

## Flags

| Flag | Description |
|------|-------------|
| `--reportRepoURL`, `-r` | Report repository URL (required) |
| `--shieldsMarkdown`, `-s` | Shields (badge) Markdown for the root index (optional) |
| `--xlsxOutputFile`, `-x` | Excel output file (optional) |

## Behavior

The tool builds a default site-home writer from the supplied options and writes the home index file. It prints `DONE` on success.

## Example

```bash
go run ./cmd/siteindex \
  --reportRepoURL "https://github.com/acme/security-reports" \
  --shieldsMarkdown "![findings](badge.svg)"
```

## Related

- [Reports Overview](../reports/index.md) - Report and site generation
