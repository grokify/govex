# Installation

## CLI Installation

Install the `govex` CLI using Go:

```bash
go install github.com/grokify/govex/cmd/govex@latest
```

Verify the installation:

```bash
govex --help
```

## Library Installation

Add GoVEX to your Go project:

```bash
go get github.com/grokify/govex@latest
```

## Requirements

- Go 1.21 or later
- For XLSX export: no additional dependencies (uses pure Go library)

## Building from Source

Clone the repository and build:

```bash
git clone https://github.com/grokify/govex.git
cd govex
go build ./cmd/govex/
```

## Verifying Installation

After installation, verify the CLI is working:

```bash
# Check version
govex --help

# Test letter command
govex letter example
```
