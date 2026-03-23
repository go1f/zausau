package scan

import (
	"path/filepath"
	"testing"

	"github.com/jyufu/sensitive-info-scan/internal/model"
	"github.com/jyufu/sensitive-info-scan/internal/rules"
)

func TestScannerFindsBuiltInFixture(t *testing.T) {
	cfg := model.Config{
		Workers:         2,
		MaxFileSize:     1 << 20,
		DefaultMinScore: 0.55,
		IgnorePaths:     []string{".git", "node_modules"},
		IgnoreExts:      []string{".png"},
		Filters: model.FilterSet{
			PlaceholderValues:   []string{"changeme"},
			PlaceholderPatterns: []string{`(?i)^(?:your_.+|<.+>|example.+)$`},
			MaskedPatterns:      []string{`^[*xX#-]{6,}$`},
			HashPatterns:        []string{`(?i)^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$`},
			UUIDPatterns:        []string{`(?i)^[a-f0-9]{8}-[a-f0-9]{4}-`},
			VariablePatterns:    []string{`^(?:\$\{[A-Z0-9_]+\}|[A-Z0-9_]{6,})$`},
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
		},
	}
	engine, err := rules.NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(cfg, engine)
	root := filepath.Join("..", "..", "testdata", "samples", "fixtures")
	result, err := scanner.ScanPath(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) == 0 {
		t.Fatalf("expected findings in fixture")
	}
}
