# govex slaletter

Generate SLA exception notification letters for security findings.

It can read from a JSON file or accept parameters directly, and output JSON IR and/or Pandoc Markdown for conversion to DOCX/PDF.

## Usage

```bash
govex slaletter [command]
```

## Subcommands

| Command | Description |
|---------|-------------|
| `generate` | Generate an SLA exception letter from JSON or command-line parameters |
| `schema` | Output JSON Schema for the SLA exception format |
| `example` | Output an example JSON file |

---

## govex slaletter generate

Generate an SLA exception letter from JSON input or command-line parameters.

### Usage

```bash
govex slaletter generate [flags]
```

### Input Options

| Flag | Description |
|------|-------------|
| `--input`, `-i` | Input JSON file |

### Output Options

| Flag | Description |
|------|-------------|
| `--output-json` | Output JSON file path |
| `--output-md` | Output Markdown file path |
| `--stdout` | Output to stdout: `json` or `md` |

At least one output is required: `--output-json`, `--output-md`, or `--stdout`.

### Customer/Application

| Flag | Description |
|------|-------------|
| `--customer` | Customer name |
| `--application` | Application name |

### Finding Details

| Flag | Description |
|------|-------------|
| `--finding-title` | Finding title |
| `--finding-severity` | Finding severity (Low, Moderate, High, Critical) |
| `--finding-id` | Finding identifier |
| `--finding-date` | Finding detection date (YYYY-MM-DD) |

### CVSS (Optional)

| Flag | Description |
|------|-------------|
| `--cvss-score` | CVSS score |
| `--cvss-version` | CVSS version (e.g., 4.0) |
| `--cvss-vector` | CVSS vector string |

### SLA Fields

| Flag | Description |
|------|-------------|
| `--sla-target-days` | SLA target days for remediation |
| `--sla-original-date` | Original SLA due date (YYYY-MM-DD) |
| `--sla-new-date` | New SLA due date (YYYY-MM-DD) |

### Delay/Risk/Mitigation

| Flag | Description |
|------|-------------|
| `--delay-reason` | Delay reason (repeatable) |
| `--risk` | Risk assessment text |
| `--mitigation` | Mitigation (repeatable) |
| `--remediation` | Remediation plan |

### Sender Information

| Flag | Description |
|------|-------------|
| `--sender-name` | Sender name |
| `--sender-title` | Sender title |
| `--sender-team` | Sender team |
| `--sender-company` | Sender company |
| `--sender-email` | Sender email |
| `--sender-phone` | Sender phone (optional) |

### Milestones (Optional)

| Flag | Description |
|------|-------------|
| `--milestone` | Milestone in `phase:description:date:impact` format (repeatable) |

### Approver (Optional)

| Flag | Description |
|------|-------------|
| `--approver-name` | Exception approver name |
| `--approver-title` | Exception approver title |
| `--approver-date` | Exception approval date (YYYY-MM-DD) |

### Escalation Policy (Optional)

| Flag | Description |
|------|-------------|
| `--escalation` | Escalation policy action (repeatable) |

### Examples

#### Generate from JSON

```bash
govex slaletter generate --input finding.json --output-md letter.md
```

#### Generate with parameters

```bash
govex slaletter generate \
  --customer "Widget Inc" \
  --application "Payments API" \
  --finding-title "Missing rate limiting" \
  --finding-severity Low \
  --finding-id APPSEC-1234 \
  --finding-date 2026-04-01 \
  --sla-target-days 90 \
  --sla-original-date 2026-06-30 \
  --sla-new-date 2026-07-31 \
  --delay-reason "Dependent on upstream API gateway change" \
  --risk "Low likelihood of exploitation due to internal-only access." \
  --mitigation "WAF rate limiting rules in place" \
  --remediation "Implement native rate limiting in service layer" \
  --sender-name "Jane Smith" \
  --sender-title "Security Engineer" \
  --sender-team "Application Security" \
  --sender-company "Acme Corp" \
  --sender-email "security@acme.com" \
  --output-json finding.json \
  --output-md letter.md
```

---

## govex slaletter schema

Output the JSON Schema that describes the SLA exception JSON format. This schema can be used by AI agents, validators, or documentation tools to understand the expected structure of the input JSON.

### Usage

```bash
govex slaletter schema [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Output file path (default: stdout) |

### Examples

```bash
# Print schema to stdout
govex slaletter schema

# Save schema to file
govex slaletter schema --output schema.json
```

---

## govex slaletter example

Output an example SLA exception JSON file that can be used as a template.

### Usage

```bash
govex slaletter example [flags]
```

### Examples

```bash
# Print example to stdout
govex slaletter example

# Save example to file
govex slaletter example > finding.json
```
