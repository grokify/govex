# Status

## Overview

Security vulnerability statuses help track the lifecycle of a vulnerability from discovery to resolution. Here are common statuses used in vulnerability management systems:

1. New/Identified
  * The vulnerability has been discovered but not yet analyzed or validated.
  * Examples:
    * A new CVE (Common Vulnerabilities and Exposures) is reported.
    * An internal system scan detects a potential issue.
2. Analyzing
  * The vulnerability is being investigated to determine its validity, impact, and scope.
  * Security teams assess the exploitability, risk, and affected systems.
3. Confirmed/Validated
  * The vulnerability is verified as legitimate and actionable.
  * Documentation includes details such as CVE identifiers, affected versions, and potential exploit paths.
4. Mitigated
  * Temporary measures or workarounds have been applied to reduce the immediate risk (e.g., disabling a vulnerable service or applying a firewall rule).
  * The issue still requires a permanent fix.
5. In Progress
  * Efforts to remediate the vulnerability (e.g., patch development, system updates) are underway.
  * May include testing fixes in development or staging environments.
6. Resolved/Fixed
  * A patch or update has been applied to address the vulnerability permanently.
  * Verified through testing and audit to confirm effectiveness.
7. Remediated
  * All affected systems and environments have been updated or patched, and the risk is eliminated.
  * Includes a formal review to confirm that remediation was comprehensive.
8. Closed
  * The vulnerability is considered resolved, and no further action is required.
  * Documentation of actions taken is archived for future reference.
9. Reopened
  * The issue re-emerges due to failed remediation, additional exploits, or recurrence.
  * Indicates the need for further investigation or updated fixes.
10. Not Applicable/False Positive
  * The vulnerability was misclassified, irrelevant, or not exploitable in the current environment.
  * Documented as a non-issue with justification.
11. Deferred/Postponed
  * Remediation is delayed due to lower priority, resource constraints, or minimal impact.
  * Often scheduled for future resolution.
12. Ignored/Accepted Risk
  * The organization decides not to address the vulnerability based on an acceptable level of risk.
  * Requires formal approval and documentation of the decision.

## Workflow Summary

Statuses typically follow a workflow such as:

New → Analyzing → Confirmed → In Progress → Resolved → Closed

or

New → Analyzing → Deferred/Ignored (for non-actionable cases).
