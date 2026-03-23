package filter

import (
	"regexp"
	"strings"

	"github.com/jyufu/sensitive-info-scan/internal/model"
)

type Filter struct {
	placeholderValues map[string]struct{}
	placeholderRegs   []*regexp.Regexp
	maskedRegs        []*regexp.Regexp
	hashRegs          []*regexp.Regexp
	uuidRegs          []*regexp.Regexp
	variableRegs      []*regexp.Regexp
}

func New(cfg model.FilterSet) (*Filter, error) {
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

	placeholderRegs, err := compile(cfg.PlaceholderPatterns)
	if err != nil {
		return nil, err
	}
	maskedRegs, err := compile(cfg.MaskedPatterns)
	if err != nil {
		return nil, err
	}
	hashRegs, err := compile(cfg.HashPatterns)
	if err != nil {
		return nil, err
	}
	uuidRegs, err := compile(cfg.UUIDPatterns)
	if err != nil {
		return nil, err
	}
	variableRegs, err := compile(cfg.VariablePatterns)
	if err != nil {
		return nil, err
	}

	values := make(map[string]struct{}, len(cfg.PlaceholderValues))
	for _, value := range cfg.PlaceholderValues {
		values[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}
	return &Filter{
		placeholderValues: values,
		placeholderRegs:   placeholderRegs,
		maskedRegs:        maskedRegs,
		hashRegs:          hashRegs,
		uuidRegs:          uuidRegs,
		variableRegs:      variableRegs,
	}, nil
}

func (f *Filter) ShouldSkip(value string) (bool, string) {
	normalized := normalize(value)
	if normalized == "" {
		return true, "empty-value"
	}
	if looksLikeEnvReference(normalized) {
		return true, "env-reference"
	}
	if _, ok := f.placeholderValues[strings.ToLower(normalized)]; ok {
		return true, "placeholder-value"
	}
	if matchAny(f.placeholderRegs, normalized) {
		return true, "placeholder-pattern"
	}
	if matchAny(f.maskedRegs, normalized) {
		return true, "masked-value"
	}
	if matchAny(f.hashRegs, normalized) {
		return true, "hash-like"
	}
	if matchAny(f.uuidRegs, normalized) {
		return true, "uuid-like"
	}
	if matchAny(f.variableRegs, normalized) {
		return true, "variable-reference"
	}
	return false, ""
}

func normalize(value string) string {
	return strings.Trim(strings.TrimSpace(value), "\"'`")
}

func matchAny(regs []*regexp.Regexp, value string) bool {
	for _, re := range regs {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func looksLikeEnvReference(value string) bool {
	if strings.HasPrefix(value, "${") {
		return true
	}
	if strings.HasPrefix(value, "process.env.") {
		return true
	}
	return false
}
