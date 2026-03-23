package learn

import (
	"testing"

	"github.com/jyufu/sensitive-info-scan/internal/model"
)

func TestSanitizedSuggestionForSimulationDropsInvalidRules(t *testing.T) {
	suggestion := model.LearnSuggestion{
		ProposedRules: []model.Rule{
			{
				ID:       "valid",
				Kind:     "regex",
				Patterns: []string{`AKIA[0-9A-Z]{16}`},
			},
			{
				ID:       "invalid",
				Kind:     "regex",
				Patterns: []string{`(?<!\d)1[3-9]\d{9}`},
			},
		},
		ProposedIgnorePaths: []string{"testdata"},
	}

	sanitized := SanitizedSuggestionForSimulation(suggestion)
	if len(sanitized.ProposedRules) != 1 {
		t.Fatalf("expected 1 compilable rule, got %d", len(sanitized.ProposedRules))
	}
	if sanitized.ProposedRules[0].ID != "valid" {
		t.Fatalf("expected valid rule to remain, got %q", sanitized.ProposedRules[0].ID)
	}
	if len(sanitized.ProposedIgnorePaths) != 1 || sanitized.ProposedIgnorePaths[0] != "testdata" {
		t.Fatalf("expected ignore paths to be preserved")
	}
}
