# govex letter

Generate security notification letters for vulnerability findings.

## Usage

```bash
govex letter [command]
```

## Subcommands

| Command | Description |
|---------|-------------|
| `generate` | Generate a letter from JSON or command-line parameters |
| `schema` | Output JSON Schema for the letter format |
| `example` | Output example JSON template |

## Letter Types

| Type | Description |
|------|-------------|
| `sla` | SLA exception notification (default) |
| `hardening` | Security hardening notice |

---

## govex letter generate

Generate a security notification letter.

### Usage

```bash
govex letter generate [flags]
```

### Input Options

| Flag | Description |
|------|-------------|
| `--input`, `-i` | Input JSON file |
| `--type`, `-t` | Letter type: `sla` or `hardening` (default: `sla`) |

### Output Options

| Flag | Description |
|------|-------------|
| `--output-json` | Output JSON file path |
| `--output-md` | Output Markdown file path |
| `--stdout` | Output to stdout: `json` or `md` |

### Customer/Application

| Flag | Description |
|------|-------------|
| `--customer` | Customer name |
| `--application` | Application name |

### Finding Details

| Flag | Description |
|------|-------------|
| `--finding-title` | Finding title |
| `--finding-severity` | Severity: Low, Moderate, High, Critical |
| `--finding-id` | Finding identifier |
| `--finding-date` | Detection date (YYYY-MM-DD) |

### CVSS (Optional)

| Flag | Description |
|------|-------------|
| `--cvss-score` | CVSS score (0.0-10.0) |
| `--cvss-version` | CVSS version (e.g., 4.0) |
| `--cvss-vector` | CVSS vector string |

### SLA Fields (type=sla)

| Flag | Description |
|------|-------------|
| `--sla-target-days` | Target days for remediation |
| `--sla-original-date` | Original due date (YYYY-MM-DD) |
| `--sla-new-date` | New due date (YYYY-MM-DD) |
| `--delay-reason` | Delay reason (repeatable) |

### Hardening Fields (type=hardening)

| Flag | Description |
|------|-------------|
| `--rationale` | Rationale for improvement |
| `--target-date` | Target completion date (YYYY-MM-DD) |

### Risk/Mitigation

| Flag | Description |
|------|-------------|
| `--risk` | Risk assessment text |
| `--mitigation` | Mitigation measure (repeatable) |
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
| `--approver-name` | Approver name |
| `--approver-title` | Approver title |
| `--approver-date` | Approval date (YYYY-MM-DD) |

### Escalation Policy (Optional)

| Flag | Description |
|------|-------------|
| `--escalation` | Escalation action (repeatable) |

### Examples

#### Generate from JSON

```bash
govex letter generate --input finding.json --output-md letter.md
```

#### Generate SLA Exception

```bash
govex letter generate \
  --type sla \
  --customer "Widget Inc" \
  --application "Payments API" \
  --finding-title "Missing rate limiting" \
  --finding-severity Low \
  --finding-id APPSEC-1234 \
  --finding-date 2026-04-01 \
  --sla-target-days 90 \
  --sla-original-date 2026-06-30 \
  --sla-new-date 2026-07-31 \
  --delay-reason "Dependent on upstream API change" \
  --risk "Low likelihood due to internal-only access" \
  --mitigation "WAF rate limiting rules in place" \
  --remediation "Implement native rate limiting" \
  --sender-name "Jane Smith" \
  --sender-title "Security Engineer" \
  --sender-team "Application Security" \
  --sender-company "Acme Corp" \
  --sender-email "security@acme.com" \
  --output-md letter.md
```

#### Generate Hardening Notice

```bash
govex letter generate \
  --type hardening \
  --customer "Widget Inc" \
  --application "Customer Portal" \
  --finding-title "CSP Configuration Enhancement" \
  --finding-severity Low \
  --finding-id APPSEC-5678 \
  --finding-date 2026-04-01 \
  --rationale "Defense-in-depth improvement to strengthen CSP" \
  --risk "Hardening opportunity, not exploitable" \
  --mitigation "Existing CSP provides baseline protection" \
  --remediation "Implement stricter CSP directives" \
  --target-date 2026-08-01 \
  --sender-name "Jane Smith" \
  --sender-title "Security Engineer" \
  --sender-team "Application Security" \
  --sender-company "Acme Corp" \
  --sender-email "security@acme.com" \
  --output-md letter.md
```

---

## govex letter schema

Output the JSON Schema for the letter format.

### Usage

```bash
govex letter schema [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Output file path (default: stdout) |

### Examples

```bash
# Print schema to stdout
govex letter schema

# Save schema to file
govex letter schema --output letter-schema.json
```

---

## govex letter example

Output an example JSON file as a template.

### Usage

```bash
govex letter example [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--type`, `-t` | Letter type: `sla` or `hardening` (default: `sla`) |

### Examples

```bash
# SLA exception example
govex letter example

# Hardening notice example
govex letter example --type hardening

# Save to file
govex letter example > finding.json
```
