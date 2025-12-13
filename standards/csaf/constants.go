package csaf

const (
	FlagLabelExploited             = "exploited"                // A flag like "exploited" might be added to indicate that the vulnerability is actively being exploited in the wild.
	FlagLabelFalsePositive         = "false_positive"           // A flag such as "false_positive" can signal that, after further analysis, the reported vulnerability is not actually a threat.
	FlagLabelMitigated             = "mitigated"                // Flags like "mitigated" or "workaround_available" can indicate that although the vulnerability exists, steps have already been taken to reduce its risk or impact.
	FlagLabelUnderInvestigation    = "under_investigation"      // The flag "under_investigation" can denote that the vulnerability is still being analyzed, and further details or mitigations might follow.
	FlagLabelWorkaroundAvailable   = "workaround_available"     // Flags like "mitigated" or "workaround_available" can indicate that although the vulnerability exists, steps have already been taken to reduce its risk or impact.
	FlagLabelOnlyInTestEnvironment = "only_in_test_environment" // Environmental or Contextual Conditions: Sometimes flags are used to indicate that the vulnerability may only be applicable under certain conditions or configurations (for example, "only_in_test_environment").

	NotesCategoryDescription     = "description"      // A detailed description of the vulnerability.
	NotesCategoryDetails         = "details"          // Additional technical details related to the vulnerability.
	NotesCategoryFAQ             = "faq"              // Frequently Asked Questions (FAQ) related to the vulnerability.
	NotesCategoryGeneral         = "general"          // General information that does not fit into other categories.
	NotesCategoryLegalDisclaimer = "legal_disclaimer" // Legal disclaimers or liability statements.
	NotesCategoryOther           = "other"            // Any additional information that does not fit into the predefined categories.

	ProductStatusFirstAffected      = "first_affected"
	ProductStatusFirstFixed         = "first_fixed"
	ProductStatusFixed              = "fixed"
	ProductStatusKnownAffected      = "known_affected"
	ProductStatusKnownNotAffected   = "known_not_affected"
	ProductStatusLastAffected       = "last_affected"
	ProductStatusLastRecommended    = "recommended"
	ProductStatusUnaffected         = "unaffected"
	ProductStatusUnderInvestigation = "under_investigation"

	ReferenceCategoryAdvisory = "advisory" // A reference to another security advisory.
	ReferenceCategoryArticle  = "article"  // A reference to a security-related article.
	ReferenceCategoryFix      = "fix"      // A reference to a patch or fix documentation.
	ReferenceCategorySelf     = "self"     // A reference to the advisory itself.
	ReferenceCategoryExternal = "external" // A reference to an external source, such as a CVE entry.
	ReferenceCategoryReport   = "report"   // A reference to a detailed security report or white paper.
	ReferenceCategoryTools    = "tools"    // A reference to tools that assist in assessing or mitigating the vulnerability.
	ReferenceCategoryVendor   = "vendor"   // A reference to vendor-specific information about the vulnerability.

	RemediationCategoryFix        = "fix"        // Indicates that a patch or update is available that completely resolves the vulnerability.
	RemediationCategoryWorkaround = "workaround" // Describes a temporary change or configuration that reduces exposure until a proper fix is released.
	RemediationCategoryMitigation = "mitigation" // Refers to measures that reduce the risk or impact of the vulnerability, even if the underlying issue isn’t fully resolved.
	RemediationCategoryNoFix      = "no_fix"     // Signifies that no fix is available, with additional context often provided to explain why or what alternative actions may be taken.
)
