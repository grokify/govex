# dedupe

Deduplicate vulnerability findings in a GoVEX vulnerabilities file.

## Overview

`cmd/dedupe` is a minimal standalone utility. It reads a vulnerabilities set from a fixed file named `vulns.json` in the current working directory, removes duplicate findings, and prints the before/after counts. There are no command-line flags — the input path is hardcoded.

## Usage

Place a `vulns.json` file in the current directory, then run:

```bash
go run github.com/grokify/govex/cmd/dedupe
```

Or from a checkout of the repository:

```bash
go run ./cmd/dedupe
```

## Behavior

The tool performs the following steps:

- Reads the vulnerabilities set from `vulns.json` via `govex.ReadFilesVulnerabilitiesSet`.
- Prints the count of vulnerabilities before deduplication.
- Deduplicates via `Vulnerabilities.Dedupe()`.
- Prints the count after deduplication.
- Prints `DONE` on success.

## Example Output

```text
COUNT (128)
COUNT (117)
DONE
```

The deduplicated results are computed in memory and the counts are reported; the tool does not write an output file. It is intended as a quick check of how many duplicate findings a set contains.

## Related

- [Core Package](../packages/core.md) - `Vulnerabilities` and the `Dedupe` method
