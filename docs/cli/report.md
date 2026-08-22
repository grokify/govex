# govex report

Generate a Markdown, HTML, PDF, or JSON vulnerability report from a GoVEX JSON file. The output format is inferred from the output file extension.

## Usage

```bash
# HTML report from a vulnerabilities set JSON
govex report -i vulns.json -o report.html

# PDF with metadata and residual columns
govex report -i vulns.json -o report.pdf \
  --title "Q3 Vulnerability Report" \
  --organization "Example Corp" \
  --classification "Confidential" \
  --columns residual

# Markdown from a saved Report JSON (metadata preserved)
govex report -i report.json -o report.md
```

## Input

The input JSON may be either:

- A **VulnerabilitiesSet** file (as produced by `govex merge`) — the set name becomes the default title.
- A **Report** file (as produced by `govex report -o report.json` or `Report.WriteJSONFile`) — stored metadata is preserved and flags override it.

## Flags

| Flag | Description |
|------|-------------|
| `-i, --input` | Input JSON file: VulnerabilitiesSet or Report (required) |
| `-o, --output` | Output file: `.md`, `.html`, `.pdf`, or `.json` (required) |
| `-t, --title` | Report title (defaults to set name) |
| `--subtitle` | Report subtitle |
| `--organization` | Organization name |
| `--author` | Report author |
| `--classification` | Classification banner, e.g. Confidential |
| `--summary` | Executive summary text |
| `--columns` | Findings columns: `default` or `residual` |

`--columns residual` renders the inherent vs. residual assessment columns (Residual Severity, Residual Risk, Exception Status, Compensating Controls) — see [Compensating Controls & Residual Risk](../reference/residual-risk.md).

## Related

- [Vulnerability Report Package](../reports/vulnreport.md) - Library API behind this command
- [govex merge](merge.md) - Produce the input VulnerabilitiesSet JSON
