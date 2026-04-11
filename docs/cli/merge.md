# govex merge

Merge multiple JSON vulnerability files into a single consolidated file.

## Usage

```bash
govex merge [flags]
```

## Flags

| Flag | Description |
|------|-------------|
| `--input`, `-i` | Input JSON file (can be specified multiple times) |
| `--output`, `-o` | Output JSON file path |

## Examples

### Merge Two Files

```bash
govex merge --input scan1.json --input scan2.json --output combined.json
```

### Merge Multiple Scanner Outputs

```bash
govex merge \
  --input semgrep-results.json \
  --input spotbugs-results.json \
  --input grype-results.json \
  --output all-vulnerabilities.json
```

## Input Format

Input files should contain vulnerability data in GoVEX JSON format:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-1234",
      "title": "SQL Injection",
      "severity": "High",
      "status": "Open"
    }
  ]
}
```

## Output

The merged output combines all vulnerabilities from input files, preserving all fields.
