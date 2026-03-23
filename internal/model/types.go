package model

type Config struct {
	Version         string    `json:"version"`
	Workers         int       `json:"workers"`
	MaxFileSize     int64     `json:"max_file_size"`
	DefaultMinScore float64   `json:"default_min_score"`
	IgnorePaths     []string  `json:"ignore_paths"`
	IgnoreExts      []string  `json:"ignore_extensions"`
	Filters         FilterSet `json:"filters"`
	Rules           []Rule    `json:"rules"`
}

type FilterSet struct {
	PlaceholderValues   []string `json:"placeholder_values"`
	PlaceholderPatterns []string `json:"placeholder_patterns"`
	MaskedPatterns      []string `json:"masked_patterns"`
	HashPatterns        []string `json:"hash_patterns"`
	UUIDPatterns        []string `json:"uuid_patterns"`
	VariablePatterns    []string `json:"variable_patterns"`
}

type Rule struct {
	ID                   string       `json:"id"`
	Name                 string       `json:"name"`
	Kind                 string       `json:"kind"`
	Category             string       `json:"category"`
	Severity             string       `json:"severity"`
	Description          string       `json:"description"`
	Keywords             []string     `json:"keywords"`
	Patterns             []string     `json:"patterns"`
	FieldPatterns        []string     `json:"field_patterns"`
	ExcludeFieldPatterns []string     `json:"exclude_field_patterns"`
	ValuePatterns        []string     `json:"value_patterns"`
	ExcludeValues        []string     `json:"exclude_values"`
	ExcludeValuePatterns []string     `json:"exclude_value_patterns"`
	Validation           string       `json:"validation"`
	MinEntropy           float64      `json:"min_entropy"`
	RequireAssignment    bool         `json:"require_assignment"`
	Score                ScoreProfile `json:"score"`
}

type ScoreProfile struct {
	Base            float64 `json:"base"`
	FieldBoost      float64 `json:"field_boost"`
	EntropyBoost    float64 `json:"entropy_boost"`
	AssignmentBoost float64 `json:"assignment_boost"`
}

type Finding struct {
	File     string  `json:"file"`
	Line     int     `json:"line"`
	Column   int     `json:"column"`
	RuleID   string  `json:"rule_id"`
	Name     string  `json:"name"`
	Category string  `json:"category"`
	Severity string  `json:"severity"`
	Score    float64 `json:"score"`
	Match    string  `json:"match"`
	Redacted string  `json:"redacted"`
	Excerpt  string  `json:"excerpt"`
	Reason   string  `json:"reason"`
}

type ScanStats struct {
	FilesScanned int   `json:"files_scanned"`
	FilesSkipped int   `json:"files_skipped"`
	BytesScanned int64 `json:"bytes_scanned"`
}

type ScanResult struct {
	Findings []Finding `json:"findings"`
	Stats    ScanStats `json:"stats"`
}

type ValidationManifest struct {
	Dataset string           `json:"dataset"`
	Cases   []ValidationCase `json:"cases"`
}

type ValidationCase struct {
	Group    string            `json:"group,omitempty"`
	File     string            `json:"file"`
	Expected []ExpectedFinding `json:"expected"`
}

type ExpectedFinding struct {
	RuleID        string `json:"rule_id"`
	Category      string `json:"category"`
	MatchContains string `json:"match_contains"`
}

type ValidationMismatch struct {
	File     string  `json:"file"`
	RuleID   string  `json:"rule_id"`
	Category string  `json:"category"`
	Match    string  `json:"match"`
	Reason   string  `json:"reason"`
	Score    float64 `json:"score"`
}

type ValidationReport struct {
	Dataset        string                `json:"dataset"`
	TruePositives  int                   `json:"true_positives"`
	FalsePositives int                   `json:"false_positives"`
	FalseNegatives int                   `json:"false_negatives"`
	Precision      float64               `json:"precision"`
	Recall         float64               `json:"recall"`
	FalseDiscovery float64               `json:"false_discovery_rate"`
	GroupStats     []ValidationGroupStat `json:"group_stats,omitempty"`
	Unexpected     []ValidationMismatch  `json:"unexpected"`
	Missed         []ValidationMismatch  `json:"missed"`
}

type ValidationGroupStat struct {
	Group          string  `json:"group"`
	TruePositives  int     `json:"true_positives"`
	FalsePositives int     `json:"false_positives"`
	FalseNegatives int     `json:"false_negatives"`
	Precision      float64 `json:"precision"`
	Recall         float64 `json:"recall"`
	FalseDiscovery float64 `json:"false_discovery_rate"`
}

type LearnSuggestion struct {
	Summary             string   `json:"summary"`
	Notes               []string `json:"notes"`
	ProposedRules       []Rule   `json:"proposed_rules"`
	ProposedIgnorePaths []string `json:"proposed_ignore_paths"`
}

type ReviewThresholds struct {
	MinPrecision      float64 `json:"min_precision"`
	MinRecall         float64 `json:"min_recall"`
	MaxFalseDiscovery float64 `json:"max_false_discovery_rate"`
}

type RuleReviewFinding struct {
	RuleID   string `json:"rule_id,omitempty"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

type ModelReview struct {
	Summary  string              `json:"summary"`
	Approved bool                `json:"approved"`
	Findings []RuleReviewFinding `json:"findings"`
}

type SuggestionReviewReport struct {
	Approved            bool                `json:"approved"`
	Thresholds          ReviewThresholds    `json:"thresholds"`
	StaticFindings      []RuleReviewFinding `json:"static_findings"`
	ModelReview         ModelReview         `json:"model_review"`
	SimulatedValidation ValidationReport    `json:"simulated_validation"`
}
