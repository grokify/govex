# CLI Overview

The `govex` CLI provides commands for vulnerability management tasks.

## Installation

```bash
go install github.com/grokify/govex/cmd/govex@latest
```

## Available Commands

| Command | Description |
|---------|-------------|
| `govex merge` | Merge multiple JSON vulnerability files |
| `govex homepage` | Generate site homepage for vulnerability reports |
| `govex letter` | Generate security notification letters |

## Global Flags

```
-h, --help    Show help for any command
```

## Usage

```bash
# Get help
govex --help

# Get help for a specific command
govex letter --help
govex letter generate --help
```

## Exit Codes

All commands return appropriate exit codes for CI/CD integration:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
