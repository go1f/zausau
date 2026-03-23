package rules

import (
	"testing"

	"github.com/jyufu/sensitive-info-scan/internal/model"
)

func TestEngineDetectsCredentialAndPhone(t *testing.T) {
	cfg := model.Config{
		DefaultMinScore: 0.55,
		Filters: model.FilterSet{
			PlaceholderPatterns: []string{`(?i)^your_.+`},
			MaskedPatterns:      []string{`^[*xX#-]{6,}$`},
			HashPatterns:        []string{`(?i)^[a-f0-9]{32}$`},
			UUIDPatterns:        []string{`(?i)^[a-f0-9]{8}-`},
			VariablePatterns:    []string{`^\$\{[A-Z0-9_]+\}$`},
		},
		Rules: []model.Rule{
			{
				ID:                "generic-credential-field",
				Name:              "Generic Credential Field",
				Kind:              "field",
				Category:          "credential",
				Severity:          "high",
				FieldPatterns:     []string{`(?i)(?:token|password|secret|api[_-]?key)`},
				ValuePatterns:     []string{`.{6,}`},
				RequireAssignment: true,
				Score: model.ScoreProfile{
					Base:            0.40,
					FieldBoost:      0.18,
					AssignmentBoost: 0.12,
				},
			},
			{
				ID:            "cn-mainland-mobile",
				Name:          "China Mainland Mobile",
				Kind:          "regex",
				Category:      "personal_contact",
				Severity:      "medium",
				Patterns:      []string{`\b1[3-9]\d{9}\b`},
				ExcludeValues: []string{"13800138000"},
				Score: model.ScoreProfile{
					Base:       0.70,
					FieldBoost: 0.06,
				},
			},
		},
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	findings := engine.ScanLine("demo.txt", 1, `token = "sk_live_abc123456789"; mobile = "13912345678"`)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if skipped := engine.ScanLine("demo.txt", 2, `token = "your_token_here"`); len(skipped) != 0 {
		t.Fatalf("expected placeholder token to be ignored")
	}
}
