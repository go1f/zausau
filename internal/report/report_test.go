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
				Redacted: "sk_***",
				Excerpt:  `api_key=<<<sk_***>>>`,
			},
			{
				File:     "b.env",
				Line:     8,
				RuleID:   "generic-credential-field",
				Category: "credential",
				Severity: "high",
				Reason:   "field=api_key",
				Score:    0.79,
				Redacted: "sk_***",
				Excerpt:  `api_key=<<<sk_***>>>`,
			},
			{
				File:     "c.env",
				Line:     3,
				RuleID:   "aws-access-key-id",
				Category: "credential",
				Severity: "high",
				Reason:   "pattern-match",
				Score:    0.88,
				Redacted: "AKI***",
				Excerpt:  `access_key=<<<AKI***>>>`,
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
	if !strings.Contains(text, "api_key=<<<sk_***>>>") {
		t.Fatalf("expected highlighted sample excerpt, got %s", text)
	}
}
