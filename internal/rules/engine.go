package rules

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jyufu/sensitive-info-scan/internal/filter"
	"github.com/jyufu/sensitive-info-scan/internal/model"
	"github.com/jyufu/sensitive-info-scan/internal/textutil"
)

var assignmentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`["']?([A-Za-z0-9_.-]{2,64})["']?\s*[:=]\s*"((?:\\.|[^"\\]){1,512})"`),
	regexp.MustCompile(`["']?([A-Za-z0-9_.-]{2,64})["']?\s*[:=]\s*'((?:\\.|[^'\\]){1,512})'`),
	regexp.MustCompile(`["']?([A-Za-z0-9_.-]{2,64})["']?\s*[:=]\s*([A-Za-z0-9_./:@,+-]{2,256})`),
}

type compiledRule struct {
	rule                 model.Rule
	patterns             []*regexp.Regexp
	fieldPatterns        []*regexp.Regexp
	excludeFieldPatterns []*regexp.Regexp
	valuePatterns        []*regexp.Regexp
	excludeValuePatterns []*regexp.Regexp
	excludeValues        map[string]struct{}
}

type Engine struct {
	rules    []compiledRule
	filter   *filter.Filter
	minScore float64
}

func NewEngine(cfg model.Config) (*Engine, error) {
	f, err := filter.New(cfg.Filters)
	if err != nil {
		return nil, fmt.Errorf("compile filters: %w", err)
	}

	compiled := make([]compiledRule, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		cr, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("compile rule %s: %w", rule.ID, err)
		}
		compiled = append(compiled, cr)
	}

	return &Engine{
		rules:    compiled,
		filter:   f,
		minScore: cfg.DefaultMinScore,
	}, nil
}

func compileRule(rule model.Rule) (compiledRule, error) {
	compile := func(patterns []string) ([]*regexp.Regexp, error) {
		out := make([]*regexp.Regexp, 0, len(patterns))
		for _, pattern := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			out = append(out, re)
		}
		return out, nil
	}

	patterns, err := compile(rule.Patterns)
	if err != nil {
		return compiledRule{}, err
	}
	fieldPatterns, err := compile(rule.FieldPatterns)
	if err != nil {
		return compiledRule{}, err
	}
	excludeFieldPatterns, err := compile(rule.ExcludeFieldPatterns)
	if err != nil {
		return compiledRule{}, err
	}
	valuePatterns, err := compile(rule.ValuePatterns)
	if err != nil {
		return compiledRule{}, err
	}
	excludeValuePatterns, err := compile(rule.ExcludeValuePatterns)
	if err != nil {
		return compiledRule{}, err
	}

	excludeValues := make(map[string]struct{}, len(rule.ExcludeValues))
	for _, value := range rule.ExcludeValues {
		excludeValues[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}

	return compiledRule{
		rule:                 rule,
		patterns:             patterns,
		fieldPatterns:        fieldPatterns,
		excludeFieldPatterns: excludeFieldPatterns,
		valuePatterns:        valuePatterns,
		excludeValuePatterns: excludeValuePatterns,
		excludeValues:        excludeValues,
	}, nil
}

func (e *Engine) ScanLine(path string, lineNo int, line string) []model.Finding {
	findings := make([]model.Finding, 0, 4)
	var (
		assignments         []assignment
		assignmentsPrepared bool
	)
	for _, rule := range e.rules {
		switch strings.ToLower(rule.rule.Kind) {
		case "regex":
			findings = append(findings, e.scanRegexRule(path, lineNo, line, rule)...)
		case "field":
			if !assignmentsPrepared {
				assignments = extractAssignments(line)
				assignmentsPrepared = true
			}
			findings = append(findings, e.scanFieldRule(path, lineNo, line, rule, assignments)...)
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Line == findings[j].Line {
			return findings[i].Column < findings[j].Column
		}
		return findings[i].Line < findings[j].Line
	})
	return dedupeFindings(findings)
}

func (e *Engine) scanRegexRule(path string, lineNo int, line string, rule compiledRule) []model.Finding {
	if len(rule.rule.Keywords) > 0 && !containsKeyword(line, rule.rule.Keywords) {
		return nil
	}

	var findings []model.Finding
	for _, re := range rule.patterns {
		indexes := re.FindAllStringIndex(line, -1)
		for _, idx := range indexes {
			match := line[idx[0]:idx[1]]
			if skip, reason := e.shouldSkipValue(match, rule); skip {
				_ = reason
				continue
			}
			if !e.isValid(rule.rule.Validation, match) {
				continue
			}
			entropy := textutil.ShannonEntropy(match)
			if rule.rule.MinEntropy > 0 && entropy < rule.rule.MinEntropy {
				continue
			}
			score := clampScore(rule.rule.Score.Base + rule.rule.Score.FieldBoost)
			if rule.rule.MinEntropy > 0 && entropy >= rule.rule.MinEntropy {
				score = clampScore(score + rule.rule.Score.EntropyBoost)
			}
			if score < e.minScore {
				continue
			}
			findings = append(findings, buildFinding(path, lineNo, idx[0]+1, line, match, rule.rule, score, "pattern-match"))
		}
	}
	return findings
}

func (e *Engine) scanFieldRule(path string, lineNo int, line string, rule compiledRule, assignments []assignment) []model.Finding {
	if rule.rule.RequireAssignment && len(assignments) == 0 {
		return nil
	}

	var findings []model.Finding
	for _, assignment := range assignments {
		if !matchAny(rule.fieldPatterns, assignment.Field) {
			continue
		}
		if matchAny(rule.excludeFieldPatterns, assignment.Field) {
			continue
		}
		if len(rule.valuePatterns) > 0 && !matchAny(rule.valuePatterns, assignment.Value) {
			continue
		}
		if skip, _ := e.shouldSkipValue(assignment.Value, rule); skip {
			continue
		}
		if !e.isValid(rule.rule.Validation, assignment.Value) {
			continue
		}

		entropy := textutil.ShannonEntropy(assignment.Value)
		if rule.rule.MinEntropy > 0 && entropy < rule.rule.MinEntropy {
			continue
		}

		score := rule.rule.Score.Base + rule.rule.Score.FieldBoost + rule.rule.Score.AssignmentBoost
		if rule.rule.MinEntropy > 0 && entropy >= rule.rule.MinEntropy {
			score += rule.rule.Score.EntropyBoost
		}
		score = clampScore(score)
		if score < e.minScore {
			continue
		}

		reason := fmt.Sprintf("field=%s", assignment.Field)
		findings = append(findings, buildFinding(path, lineNo, assignment.Column, line, assignment.Value, rule.rule, score, reason))
	}
	return findings
}

func (e *Engine) shouldSkipValue(value string, rule compiledRule) (bool, string) {
	normalized := strings.ToLower(strings.Trim(strings.TrimSpace(value), "\"'`"))
	if _, ok := rule.excludeValues[normalized]; ok {
		return true, "rule-excluded-value"
	}
	for _, re := range rule.excludeValuePatterns {
		if re.MatchString(value) {
			return true, "rule-excluded-pattern"
		}
	}
	return e.filter.ShouldSkip(value)
}

func (e *Engine) isValid(kind, value string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "":
		return true
	case "cn_id_checksum":
		return validChineseID(value)
	default:
		return true
	}
}

type assignment struct {
	Field  string
	Value  string
	Column int
}

func extractAssignments(line string) []assignment {
	var out []assignment
	seen := make(map[string]assignment)
	order := make([]string, 0, 4)
	for index, pattern := range assignmentPatterns {
		matches := pattern.FindAllStringSubmatchIndex(line, -1)
		for _, match := range matches {
			field := strings.TrimSpace(line[match[2]:match[3]])
			value := strings.TrimSpace(line[match[4]:match[5]])
			if index < 2 {
				quote := `"`
				if index == 1 {
					quote = `'`
				}
				if unquoted, err := strconv.Unquote(quote + value + quote); err == nil {
					value = unquoted
				}
			}
			key := fmt.Sprintf("%s\x00%d", field, match[4]+1)
			candidate := assignment{
				Field:  field,
				Value:  strings.TrimRight(value, ","),
				Column: match[4] + 1,
			}
			if existing, ok := seen[key]; ok {
				if len(candidate.Value) <= len(existing.Value) {
					continue
				}
				seen[key] = candidate
				continue
			}
			seen[key] = candidate
			order = append(order, key)
		}
	}
	for _, key := range order {
		out = append(out, seen[key])
	}
	return out
}

func containsKeyword(line string, keywords []string) bool {
	lower := strings.ToLower(line)
	for _, keyword := range keywords {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func matchAny(regs []*regexp.Regexp, value string) bool {
	for _, re := range regs {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func buildFinding(path string, lineNo, column int, line, match string, rule model.Rule, score float64, reason string) model.Finding {
	redacted := redact(match)
	return model.Finding{
		File:     path,
		Line:     lineNo,
		Column:   column,
		RuleID:   rule.ID,
		Name:     rule.Name,
		Category: rule.Category,
		Severity: rule.Severity,
		Score:    score,
		Match:    match,
		Redacted: redacted,
		Excerpt:  buildExcerpt(line, match, redacted),
		Reason:   reason,
	}
}

func buildExcerpt(line, match, redacted string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return line
	}
	idx, matchedText := findExcerptMatch(line, match)
	if idx < 0 {
		return trimExcerpt(line)
	}
	const contextWidth = 60
	start := idx - contextWidth
	if start < 0 {
		start = 0
	}
	end := idx + len(matchedText) + contextWidth
	if end > len(line) {
		end = len(line)
	}

	var out strings.Builder
	if start > 0 {
		out.WriteString("...")
	}
	out.WriteString(strings.TrimSpace(line[start:idx]))
	if out.Len() > 0 && !strings.HasSuffix(out.String(), " ") {
		out.WriteByte(' ')
	}
	out.WriteString("<<<")
	out.WriteString(redacted)
	out.WriteString(">>>")
	if idx+len(matchedText) < end {
		suffix := strings.TrimSpace(line[idx+len(matchedText) : end])
		if suffix != "" {
			out.WriteByte(' ')
			out.WriteString(suffix)
		}
	}
	if end < len(line) {
		out.WriteString("...")
	}
	return out.String()
}

func findExcerptMatch(line, match string) (int, string) {
	if idx := strings.Index(line, match); idx >= 0 {
		return idx, match
	}
	escaped := strings.Trim(strconv.Quote(match), `"`)
	if escaped != match {
		if idx := strings.Index(line, escaped); idx >= 0 {
			return idx, escaped
		}
	}
	return -1, ""
}

func trimExcerpt(line string) string {
	line = strings.TrimSpace(line)
	if len(line) <= 160 {
		return line
	}
	return line[:157] + "..."
}

func redact(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= 6 {
		return "***"
	}
	sum := sha1.Sum([]byte(trimmed))
	return trimmed[:3] + "***" + trimmed[len(trimmed)-2:] + "#" + hex.EncodeToString(sum[:])[:8]
}

func dedupeFindings(input []model.Finding) []model.Finding {
	seen := make(map[string]model.Finding, len(input))
	for _, finding := range input {
		key := fmt.Sprintf("%s:%d:%s", finding.File, finding.Line, finding.Match)
		existing, ok := seen[key]
		if ok && existing.Score >= finding.Score {
			continue
		}
		seen[key] = finding
	}
	out := make([]model.Finding, 0, len(seen))
	for _, finding := range seen {
		out = append(out, finding)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File == out[j].File {
			if out[i].Line == out[j].Line {
				return out[i].Column < out[j].Column
			}
			return out[i].Line < out[j].Line
		}
		return out[i].File < out[j].File
	})
	return out
}

func clampScore(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 0.99 {
		return 0.99
	}
	return value
}

func validChineseID(value string) bool {
	value = strings.ToUpper(strings.Trim(strings.TrimSpace(value), "\"'`"))
	if len(value) != 18 {
		return false
	}
	weights := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checks := []byte("10X98765432")
	sum := 0
	for i := 0; i < 17; i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
		sum += int(value[i]-'0') * weights[i]
	}
	last := value[17]
	return last == checks[sum%11]
}
