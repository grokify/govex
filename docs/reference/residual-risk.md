# Compensating Controls & Residual Risk

GoVEX models the severity of a vulnerability **before** and **after** compensating controls, without ever relabeling the original assessment. This preserves the auditable chain:

> Finding severity → compensating controls → residual severity / residual risk → exception approval → SLA.

## The Four Measures

| Measure | Field | Scale | Derived From |
|---------|-------|-------|--------------|
| Inherent severity | `Vulnerability.Severity` | Critical, High, Medium, Low, Informational, None | CVSS base score |
| Residual severity | `Vulnerability.SeverityResidual` | Critical, High, Medium, Low | CVSS environmental score |
| Inherent risk | `Vulnerability.RiskInherent` | Critical, High, Medium, Low (+ Negligible) | Likelihood × impact matrix, without controls |
| Residual risk | `Vulnerability.RiskResidual` | Critical, High, Medium, Low (+ Negligible) | Likelihood × impact matrix, with verified controls |

Key distinctions:

- **Severity** is technical and recomputable: it comes from a CVSS score with published rating bands. Residual severity is derived from a CVSS *environmental* vector (`SeverityResidualVector`) justified by the vulnerability's controls.
- **Risk** is an organizational judgment: likelihood × impact looked up in an explicit risk matrix ([risk package](../packages/risk.md)). It captures what CVSS cannot — asset criticality, data sensitivity, detective controls.
- The residual **risk** convinces the exception approver; the approval activates the residual **severity**; the residual severity drives the SLA.

## Compensating Controls

A `CompensatingControl` reduces exploitability or impact without remediating the vulnerability:

```go
control := govex.CompensatingControl{
    ID:              "CTRL-NET-001",
    Name:            "Network segmentation",
    Function:        govex.ControlFunctionPreventive,
    Reduces:         []string{govex.ReducesLikelihood},
    ModifiedMetrics: []string{"MAV:A"}, // CVSS environmental metric this control justifies
    Effectiveness:   govex.EffectivenessHigh,
    Verified:        true,
    VerifiedMethod:  "external-reachability-test",
}
```

`ModifiedMetrics` is the load-bearing link: it records which CVSS environmental metric change each control justifies, so the residual severity vector is *derived from controls* rather than asserted independently.

Detective controls (monitoring, WAF rules) typically modify no CVSS metric — per FIRST guidance, a WAF does not change Modified Attack Vector. Such controls still reduce residual *risk* and support its `Rationale`, but should not shrink the SLA-driving residual severity.

## Exceptions and the SLA Clock

The SLA policy is: **the SLA clock runs on inherent severity until an exception is approved, then on residual severity.**

```go
vn := govex.Vulnerability{
    Severity:         "High",
    SeverityResidual: "Low",
    Exception: &govex.ExceptionStatus{
        Status:     govex.ExceptionStatusApproved,
        ApprovedAt: &approvedTime,
        ExpiresAt:  &expiryTime,
    },
}

sev := vn.EffectiveSeverity(time.Now()) // "Low" while approval is in effect
```

`EffectiveSeverity` returns:

- Inherent severity when no residual severity is set, no exception exists, or the exception is only requested or rejected.
- Residual severity while an approved, unexpired exception is in effect.
- Inherent severity again after the exception expires.

All SLA methods (`SLAOverdueDuration`, `SLACompliant`, `SLAInfo`, `BuildSLAStatusString`) key off `EffectiveSeverity`, so an approved exception moves the vulnerability onto the residual severity's SLA timeline automatically.

## Validation Rules

`ValidateResidualSeverity` enforces:

1. **Residual severity is Critical–Low only.** Informational and None are rejected: Informational is an inherent-only classification for non-vulnerability findings, and "not exploitable" is an exception or VEX status (`not_affected`), not a severity of None.
2. **Residual can never exceed inherent.** Controls cannot make a vulnerability worse; if the environment amplifies it, that is a separate finding.
3. **Absent means absent.** An unset residual severity falls back to inherent — do not populate it with Unknown.

## What Belongs Where

GoVEX owns the per-vulnerability record: findings, severities, controls, exceptions, SLAs. Broader risk modeling — assets, attack paths, multi-finding risks, org-level risk registers — belongs in a threat-model layer that references GoVEX findings by ID.

## Related

- [Risk Package](../packages/risk.md) - Risk ratings, matrices, and NIST SP 800-30 translation
- [CVSS Support](../standards/cvss.md) - Qualitative severity rating scales by CVSS version
- [SLA Management](sla.md) - SLA policies and effective severity
- [Vulnerability Report](../reports/vulnreport.md) - Rendering residual columns in Markdown/HTML/PDF
