# GoVEX Roadmap

Roadmap items (RMIs) carry stable IDs of the form `RMI-GOVEX-<NNN>`. Commits
implementing an RMI reference it with a `Refs: RMI-GOVEX-<NNN>` git trailer.
Phase status is derived from member RMI statuses.

## Phase 1: Residual Risk & Reporting

Model vulnerability severity and risk before and after compensating controls,
aligned with NVD CVSS qualitative ratings and NIST SP 800-30, and render
titled reports in Markdown, HTML, and PDF.

| RMI | Title | Status |
|-----|-------|--------|
| RMI-GOVEX-001 | Version-specific CVSS qualitative severity rating scales aligned with NVD | Completed |
| RMI-GOVEX-002 | Risk package: likelihood × impact ratings, explicit matrices, NIST SP 800-30 translation | Completed |
| RMI-GOVEX-003 | Residual severity, compensating controls, and exception model with effective-severity SLA switching | Completed |
| RMI-GOVEX-004 | vulnreport package: titled Markdown/HTML/PDF reports with per-finding detail sections | Completed |
| RMI-GOVEX-005 | `govex report` CLI subcommand generating reports from JSON input | Completed |

## Phase 2: Candidates (Unscheduled)

| RMI | Title | Status |
|-----|-------|--------|
| RMI-GOVEX-006 | Broader Finding model beyond vulnerabilities (misconfiguration, secret exposure, control failure) | Proposed |
| RMI-GOVEX-007 | Residual severity derivation from CVSS environmental vectors via control ModifiedMetrics | Proposed |
| RMI-GOVEX-008 | Migrate exceptionrequest package onto shared control/exception types | Proposed |
