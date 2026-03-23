package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/jyufu/sensitive-info-scan/internal/model"
)

func TestRunLearnSimulatesValidationEvenWithBlockingStaticFindings(t *testing.T) {
	tmpDir := t.TempDir()
	fixtureDir := filepath.Join(tmpDir, "testdata")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fixturePath := filepath.Join(fixtureDir, "sample.env")
	if err := os.WriteFile(fixturePath, []byte("token = sk_live_abc123456789XYZ\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := model.Config{
		Version:         "test",
		Workers:         1,
		MaxFileSize:     1 << 20,
		DefaultMinScore: 0.55,
		Filters: model.FilterSet{
			PlaceholderPatterns: []string{`(?i)^your_.+`, `(?i)^<.+>$`},
			MaskedPatterns:      []string{`^[*xX#-]{6,}$`},
			HashPatterns:        []string{`(?i)^[a-f0-9]{32,64}$`},
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
				FieldPatterns:     []string{`(?i)^token$`},
				ValuePatterns:     []string{`^[^\s]{8,}$`},
				RequireAssignment: true,
				Score: model.ScoreProfile{
					Base:            0.45,
					FieldBoost:      0.10,
					AssignmentBoost: 0.10,
				},
			},
		},
	}
	cfgPath := filepath.Join(tmpDir, "rules.json")
	writeJSON(t, cfgPath, cfg)

	manifest := model.ValidationManifest{
		Dataset: "test-learn-review",
		Cases: []model.ValidationCase{
			{
				File: fixturePath,
				Expected: []model.ExpectedFinding{
					{
						RuleID:        "generic-credential-field",
						Category:      "credential",
						MatchContains: "sk_live_abc123456789XYZ",
					},
				},
			},
		},
	}
	manifestPath := filepath.Join(tmpDir, "manifest.json")
	writeJSON(t, manifestPath, manifest)

	promptPath := filepath.Join(tmpDir, "prompt.md")
	if err := os.WriteFile(promptPath, []byte("Return strict JSON."), 0o644); err != nil {
		t.Fatal(err)
	}
	reviewPromptPath := filepath.Join(tmpDir, "review.md")
	if err := os.WriteFile(reviewPromptPath, []byte("Return strict JSON."), 0o644); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch calls.Add(1) {
		case 1:
			fmt.Fprint(w, `{"choices":[{"message":{"content":"{\"summary\":\"proposal\",\"notes\":[],\"proposed_rules\":[],\"proposed_ignore_paths\":[\"testdata\"]}"}}]}`)
		default:
			fmt.Fprint(w, `{"choices":[{"message":{"content":"{\"summary\":\"reviewed\",\"approved\":false,\"findings\":[{\"severity\":\"high\",\"source\":\"model-review\",\"title\":\"Broad ignore path\",\"detail\":\"Ignoring testdata will drop recall in regression suites.\"}]}"}}]}`)
		}
	}))
	defer server.Close()

	suggestionOut := filepath.Join(tmpDir, "rule-suggestions.json")
	reviewOut := filepath.Join(tmpDir, "rule-review.json")
	err := Run([]string{
		"learn",
		"-config", cfgPath,
		"-manifest", manifestPath,
		"-endpoint", server.URL + "/v1/chat/completions",
		"-model", "gpt-4.1",
		"-prompt", promptPath,
		"-review-prompt", reviewPromptPath,
		"-out", suggestionOut,
		"-review-out", reviewOut,
	})
	if err != nil {
		t.Fatal(err)
	}

	var report model.SuggestionReviewReport
	data, err := os.ReadFile(reviewOut)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}

	if report.SimulatedValidation.FalseNegatives != 1 {
		t.Fatalf("expected simulated false negatives to be 1, got %d", report.SimulatedValidation.FalseNegatives)
	}
	if report.SimulatedValidation.Recall != 0 {
		t.Fatalf("expected simulated recall to be 0, got %f", report.SimulatedValidation.Recall)
	}
	if len(report.StaticFindings) == 0 {
		t.Fatalf("expected static findings to be present")
	}
	if report.ModelReview.Summary != "reviewed" {
		t.Fatalf("expected model review to run, got %q", report.ModelReview.Summary)
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
