package semgrep

import (
	"encoding/json"
	"io"
	"os"
)

// Output represents the top-level Semgrep JSON output structure
type Output struct {
	Version          string   `json:"version"`
	Results          []Result `json:"results"`
	Errors           []any    `json:"errors"`
	Paths            Paths    `json:"paths"`
	Time             Time     `json:"time"`
	EngineRequested  string   `json:"engine_requested"`
	SkippedRules     []any    `json:"skipped_rules"`
	ProfilingResults []any    `json:"profiling_results"`
}

// ParseFileJSON parses semgrep JSON schema output.
func ParseJSONFromFile(filename string) (*Output, error) {
	if f, err := os.Open(filename); err != nil {
		return nil, err
	} else {
		return ParseJSON(f)
	}
}

func ParseJSON(r io.Reader) (*Output, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	out := &Output{}
	return out, json.Unmarshal(b, out)
}

// Result represents a single finding from Semgrep
type Result struct {
	CheckID string   `json:"check_id"`
	Path    string   `json:"path"`
	Start   Position `json:"start"`
	End     Position `json:"end"`
	Extra   Extra    `json:"extra"`
}

// Position represents a location in source code
type Position struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

// Extra contains additional information about a finding
type Extra struct {
	Message         string   `json:"message"`
	Fix             string   `json:"fix,omitempty"`
	Metadata        Metadata `json:"metadata"`
	Severity        string   `json:"severity"`
	Fingerprint     string   `json:"fingerprint"`
	Lines           string   `json:"lines"`
	ValidationState string   `json:"validation_state"`
	EngineKind      string   `json:"engine_kind"`
}

// Metadata contains metadata about the rule and vulnerability
type Metadata struct {
	FunctionalCategories []string `json:"functional-categories,omitempty"`
	CWE                  []string `json:"cwe,omitempty"`
	OWASP                []string `json:"owasp,omitempty"`
	SourceRuleURL        string   `json:"source-rule-url,omitempty"`
	SourceRuleUrl        string   `json:"source_rule_url,omitempty"` // Alternative field name
	ASVS                 *ASVS    `json:"asvs,omitempty"`
	References           []string `json:"references,omitempty"`
	Category             string   `json:"category,omitempty"`
	Technology           []string `json:"technology,omitempty"`
	Subcategory          []string `json:"subcategory,omitempty"`
	Likelihood           string   `json:"likelihood,omitempty"`
	Impact               string   `json:"impact,omitempty"`
	Confidence           string   `json:"confidence,omitempty"`
	License              string   `json:"license,omitempty"`
	VulnerabilityClass   []string `json:"vulnerability_class,omitempty"`
	Source               string   `json:"source,omitempty"`
	Shortlink            string   `json:"shortlink,omitempty"`
	CWE2022Top25         bool     `json:"cwe2022-top25,omitempty"`
	CWE2021Top25         bool     `json:"cwe2021-top25,omitempty"`
}

// ASVS represents Application Security Verification Standard metadata
type ASVS struct {
	ControlID  string `json:"control_id"`
	ControlURL string `json:"control_url"`
	Section    string `json:"section"`
	Version    string `json:"version"`
}

// Paths contains information about scanned paths
type Paths struct {
	Scanned []string `json:"scanned"`
}

// Time contains timing and performance information
type Time struct {
	Rules            []interface{}  `json:"rules"`
	RulesParseTime   float64        `json:"rules_parse_time"`
	ProfilingTimes   ProfilingTimes `json:"profiling_times"`
	ParsingTime      ParsingTime    `json:"parsing_time"`
	ScanningTime     ScanningTime   `json:"scanning_time"`
	MatchingTime     MatchingTime   `json:"matching_time"`
	TaintingTime     TaintingTime   `json:"tainting_time"`
	FixpointTimeouts []interface{}  `json:"fixpoint_timeouts"`
	Prefiltering     Prefiltering   `json:"prefiltering"`
	Targets          []interface{}  `json:"targets"`
	TotalBytes       int            `json:"total_bytes"`
	MaxMemoryBytes   int            `json:"max_memory_bytes"`
}

// ProfilingTimes contains overall profiling timing data
type ProfilingTimes struct {
	ConfigTime  float64 `json:"config_time"`
	CoreTime    float64 `json:"core_time"`
	IgnoresTime float64 `json:"ignores_time"`
	TotalTime   float64 `json:"total_time"`
}

// ParsingTime contains parsing performance statistics
type ParsingTime struct {
	TotalTime     float64       `json:"total_time"`
	PerFileTime   PerFileTime   `json:"per_file_time"`
	VerySlowStats VerySlowStats `json:"very_slow_stats"`
	VerySlowFiles []interface{} `json:"very_slow_files"`
}

// ScanningTime contains scanning performance statistics
type ScanningTime struct {
	TotalTime     float64       `json:"total_time"`
	PerFileTime   PerFileTime   `json:"per_file_time"`
	VerySlowStats VerySlowStats `json:"very_slow_stats"`
	VerySlowFiles []interface{} `json:"very_slow_files"`
}

// MatchingTime contains matching performance statistics
type MatchingTime struct {
	TotalTime            float64       `json:"total_time"`
	PerFileAndRuleTime   PerFileTime   `json:"per_file_and_rule_time"`
	VerySlowStats        VerySlowStats `json:"very_slow_stats"`
	VerySlowRulesOnFiles []interface{} `json:"very_slow_rules_on_files"`
}

// TaintingTime contains tainting analysis performance statistics
type TaintingTime struct {
	TotalTime           float64       `json:"total_time"`
	PerDefAndRuleTime   PerFileTime   `json:"per_def_and_rule_time"`
	VerySlowStats       VerySlowStats `json:"very_slow_stats"`
	VerySlowRulesOnDefs []interface{} `json:"very_slow_rules_on_defs"`
}

// PerFileTime contains average timing statistics
type PerFileTime struct {
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
}

// VerySlowStats contains statistics about slow operations
type VerySlowStats struct {
	TimeRatio  float64 `json:"time_ratio"`
	CountRatio float64 `json:"count_ratio"`
}

// Prefiltering contains prefiltering performance statistics
type Prefiltering struct {
	ProjectLevelTime                float64 `json:"project_level_time"`
	FileLevelTime                   float64 `json:"file_level_time"`
	RulesWithProjectPrefiltersRatio float64 `json:"rules_with_project_prefilters_ratio"`
	RulesWithFilePrefiltersRatio    float64 `json:"rules_with_file_prefilters_ratio"`
	RulesSelectedRatio              float64 `json:"rules_selected_ratio"`
	RulesMatchedRatio               float64 `json:"rules_matched_ratio"`
}
