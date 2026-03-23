package learn

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/jyufu/sensitive-info-scan/internal/model"
)

var broadIgnoreTokens = map[string]struct{}{
	".":        {},
	"src":      {},
	"app":      {},
	"cmd":      {},
	"pkg":      {},
	"internal": {},
	"lib":      {},
	"docs":     {},
	"doc":      {},
	"test":     {},
	"tests":    {},
	"examples": {},
	"fixtures": {},
	"testdata": {},
}

var genericFieldTokens = map[string]struct{}{
	"id":     {},
	"name":   {},
	"number": {},
	"value":  {},
	"data":   {},
}

var sensitiveFieldHints = []string{
	"password", "secret", "token", "key", "cookie", "session", "seed", "phone",
	"mobile", "address", "location", "face", "fingerprint", "iris", "gene",
}

func MergeSuggestion(base model.Config, suggestion model.LearnSuggestion) model.Config {
	merged := base
	ruleIndex := make(map[string]int, len(merged.Rules))
	for i, rule := range merged.Rules {
		ruleIndex[rule.ID] = i
	}
	for _, proposed := range suggestion.ProposedRules {
		if idx, ok := ruleIndex[proposed.ID]; ok {
			merged.Rules[idx] = proposed
			continue
		}
		merged.Rules = append(merged.Rules, proposed)
	}

	ignoreSet := make(map[string]struct{}, len(merged.IgnorePaths)+len(suggestion.ProposedIgnorePaths))
	mergedIgnore := make([]string, 0, len(merged.IgnorePaths)+len(suggestion.ProposedIgnorePaths))
	for _, item := range merged.IgnorePaths {
		key := strings.TrimSpace(item)
		if key == "" {
			continue
		}
		if _, ok := ignoreSet[key]; ok {
			continue
		}
		ignoreSet[key] = struct{}{}
		mergedIgnore = append(mergedIgnore, key)
	}
	for _, item := range suggestion.ProposedIgnorePaths {
		key := strings.TrimSpace(item)
		if key == "" {
			continue
		}
		if _, ok := ignoreSet[key]; ok {
			continue
		}
		ignoreSet[key] = struct{}{}
		mergedIgnore = append(mergedIgnore, key)
	}
	sort.Strings(mergedIgnore)
	merged.IgnorePaths = mergedIgnore
	return merged
}

func StaticReviewSuggestion(suggestion model.LearnSuggestion) []model.RuleReviewFinding {
	var findings []model.RuleReviewFinding

	for _, token := range suggestion.ProposedIgnorePaths {
		key := strings.ToLower(strings.TrimSpace(token))
		if _, ok := broadIgnoreTokens[key]; ok {
			findings = append(findings, model.RuleReviewFinding{
				Severity: "high",
				Source:   "static",
				Title:    "Broad ignore path proposal",
				Detail:   fmt.Sprintf("ignore path %q is broad enough to hide real findings and should not be auto-accepted", token),
			})
		}
	}

	for _, rule := range suggestion.ProposedRules {
		if strings.EqualFold(rule.Kind, "field") {
			if len(rule.ValuePatterns) == 0 && rule.MinEntropy == 0 && !rule.RequireAssignment {
				findings = append(findings, model.RuleReviewFinding{
					RuleID:   rule.ID,
					Severity: "high",
					Source:   "static",
					Title:    "Field rule lacks value guardrails",
					Detail:   "field rule has no value_patterns, no entropy gate, and does not require assignment context",
				})
			}
			if looksTooGeneric(rule.FieldPatterns) {
				findings = append(findings, model.RuleReviewFinding{
					RuleID:   rule.ID,
					Severity: "high",
					Source:   "static",
					Title:    "Field pattern is too generic",
					Detail:   "field_patterns appear to rely on generic names such as id/name/number/value without strong sensitive context",
				})
			}
		}
		if strings.EqualFold(rule.Kind, "regex") && len(rule.Keywords) == 0 && rule.MinEntropy == 0 && len(rule.Patterns) > 0 {
			shortPattern := true
			for _, pattern := range rule.Patterns {
				if len(pattern) >= 20 {
					shortPattern = false
					break
				}
			}
			if shortPattern {
				findings = append(findings, model.RuleReviewFinding{
					RuleID:   rule.ID,
					Severity: "medium",
					Source:   "static",
					Title:    "Regex rule may be too broad",
					Detail:   "regex rule has no keyword prefilter or entropy gate and patterns are short enough to warrant manual review",
				})
			}
		}
	}

	return findings
}

func CompileReviewSuggestion(suggestion model.LearnSuggestion) []model.RuleReviewFinding {
	var findings []model.RuleReviewFinding
	check := func(ruleID, kind string, patterns []string) {
		for _, pattern := range patterns {
			if _, err := regexp.Compile(pattern); err != nil {
				findings = append(findings, model.RuleReviewFinding{
					RuleID:   ruleID,
					Severity: "critical",
					Source:   "static",
					Title:    "Rule pattern is not Go-regexp compatible",
					Detail:   fmt.Sprintf("%s pattern %q does not compile with Go regexp: %v", kind, pattern, err),
				})
			}
		}
	}
	for _, rule := range suggestion.ProposedRules {
		check(rule.ID, "patterns", rule.Patterns)
		check(rule.ID, "field_patterns", rule.FieldPatterns)
		check(rule.ID, "value_patterns", rule.ValuePatterns)
		check(rule.ID, "exclude_value_patterns", rule.ExcludeValuePatterns)
	}
	return findings
}

func SanitizedSuggestionForSimulation(suggestion model.LearnSuggestion) model.LearnSuggestion {
	sanitized := suggestion
	sanitized.ProposedRules = make([]model.Rule, 0, len(suggestion.ProposedRules))
	for _, rule := range suggestion.ProposedRules {
		if !ruleCompiles(rule) {
			continue
		}
		sanitized.ProposedRules = append(sanitized.ProposedRules, rule)
	}
	return sanitized
}

func (c *Client) ReviewSuggestion(ctx context.Context, cfg model.Config, suggestion model.LearnSuggestion, validation model.ValidationReport, staticFindings []model.RuleReviewFinding, templatePath string) (model.ModelReview, error) {
	var review model.ModelReview
	templateData, err := os.ReadFile(templatePath)
	if err != nil {
		return review, fmt.Errorf("read review template: %w", err)
	}
	prompt := buildReviewPrompt(string(templateData), cfg, suggestion, validation, staticFindings)
	content, err := c.complete(ctx, prompt)
	if err != nil {
		return review, err
	}
	if err := json.Unmarshal([]byte(content), &review); err != nil {
		return review, fmt.Errorf("parse model review JSON: %w", err)
	}
	return review, nil
}

func BuildReviewReport(thresholds model.ReviewThresholds, staticFindings []model.RuleReviewFinding, modelReview model.ModelReview, validation model.ValidationReport) model.SuggestionReviewReport {
	approved := true
	for _, finding := range staticFindings {
		if isBlockingSeverity(finding.Severity) {
			approved = false
			break
		}
	}
	if modelReview.Summary != "" && !modelReview.Approved {
		approved = false
	}
	if validation.Precision < thresholds.MinPrecision || validation.Recall < thresholds.MinRecall || validation.FalseDiscovery > thresholds.MaxFalseDiscovery {
		approved = false
	}
	return model.SuggestionReviewReport{
		Approved:            approved,
		Thresholds:          thresholds,
		StaticFindings:      staticFindings,
		ModelReview:         modelReview,
		SimulatedValidation: validation,
	}
}

func buildReviewPrompt(template string, cfg model.Config, suggestion model.LearnSuggestion, validation model.ValidationReport, staticFindings []model.RuleReviewFinding) string {
	type compactRule struct {
		ID            string   `json:"id"`
		Kind          string   `json:"kind"`
		Category      string   `json:"category"`
		FieldPatterns []string `json:"field_patterns,omitempty"`
		Patterns      []string `json:"patterns,omitempty"`
	}
	baseRules := make([]compactRule, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		baseRules = append(baseRules, compactRule{
			ID:            rule.ID,
			Kind:          rule.Kind,
			Category:      rule.Category,
			FieldPatterns: rule.FieldPatterns,
			Patterns:      rule.Patterns,
		})
	}
	baseJSON, _ := json.MarshalIndent(baseRules, "", "  ")
	suggestionJSON, _ := json.MarshalIndent(suggestion, "", "  ")
	validationJSON, _ := json.MarshalIndent(validation, "", "  ")
	staticJSON, _ := json.MarshalIndent(staticFindings, "", "  ")

	replacer := strings.NewReplacer(
		"{{BASE_RULES_JSON}}", string(baseJSON),
		"{{SUGGESTION_JSON}}", string(suggestionJSON),
		"{{SIMULATED_VALIDATION_JSON}}", string(validationJSON),
		"{{STATIC_FINDINGS_JSON}}", string(staticJSON),
	)
	return replacer.Replace(template)
}

func looksTooGeneric(patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		lower := strings.ToLower(pattern)
		hasSensitiveHint := false
		for _, hint := range sensitiveFieldHints {
			if strings.Contains(lower, hint) {
				hasSensitiveHint = true
				break
			}
		}
		if hasSensitiveHint {
			return false
		}
		for token := range genericFieldTokens {
			if strings.Contains(lower, token) {
				return true
			}
		}
	}
	return false
}

func ruleCompiles(rule model.Rule) bool {
	return patternsCompile(rule.Patterns) &&
		patternsCompile(rule.FieldPatterns) &&
		patternsCompile(rule.ExcludeFieldPatterns) &&
		patternsCompile(rule.ValuePatterns) &&
		patternsCompile(rule.ExcludeValuePatterns)
}

func patternsCompile(patterns []string) bool {
	for _, pattern := range patterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return false
		}
	}
	return true
}

func isBlockingSeverity(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "high" || value == "critical"
}
