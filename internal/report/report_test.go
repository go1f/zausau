package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jyufu/sensitive-info-scan/internal/model"
)

func TestWriteScanCSVSummaryGroupsSimilarFindings(t *testing.T) {
	result := model.ScanResult{
		Findings: []model.Finding{
			{
				File:     "a.env",
				Line:     1,
				RuleID:   "generic-credential-field",
				Category: "credential",
				Severity: "high",
				Reason:   "field=api_key",
				Score:    0.82,
				Match:    "sk_live_abc123",
				Redacted: "sk_live_abc123",
				Excerpt:  `api_key=<<<sk_live_abc123>>>`,
			},
			{
				File:     "b.env",
				Line:     8,
				RuleID:   "generic-credential-field",
				Category: "credential",
				Severity: "high",
				Reason:   "field=api_key",
				Score:    0.79,
				Match:    "sk_live_abc123",
				Redacted: "sk_live_abc123",
				Excerpt:  `api_key=<<<sk_live_abc123>>>`,
			},
			{
				File:     "c.env",
				Line:     3,
				RuleID:   "aws-access-key-id",
				Category: "credential",
				Severity: "high",
				Reason:   "pattern-match",
				Score:    0.88,
				Match:    "AKIAIOSFODNN7EXAMPLE",
				Redacted: "AKIAIOSFODNN7EXAMPLE",
				Excerpt:  `access_key=<<<AKIAIOSFODNN7EXAMPLE>>>`,
			},
		},
	}

	var out bytes.Buffer
	if err := WriteScanCSVSummary(&out, result); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	if !strings.Contains(text, "generic-credential-field,credential,high,field=api_key,2,2,0.82") {
		t.Fatalf("expected grouped csv row, got %s", text)
	}
	if !strings.Contains(text, "aws-access-key-id,credential,high,pattern-match,1,1,0.88") {
		t.Fatalf("expected second grouped row, got %s", text)
	}
	if !strings.Contains(text, "api_key=<<<sk_live_abc123>>>") {
		t.Fatalf("expected highlighted sample excerpt, got %s", text)
	}
	if !strings.Contains(text, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("expected raw sample match in csv, got %s", text)
	}
}
