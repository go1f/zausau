package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/jyufu/sensitive-info-scan/internal/model"
)

func WriteJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func WriteScanText(w io.Writer, result model.ScanResult) error {
	if err := WriteScanSummaryText(w, result); err != nil {
		return err
	}
	for _, finding := range result.Findings {
		if err := WriteFindingText(w, finding); err != nil {
			return err
		}
	}
	return nil
}

func WriteScanSummaryText(w io.Writer, result model.ScanResult) error {
	if _, err := fmt.Fprintf(w, "Scanned %d files, skipped %d, bytes %d, findings %d\n",
		result.Stats.FilesScanned,
		result.Stats.FilesSkipped,
		result.Stats.BytesScanned,
		len(result.Findings),
	); err != nil {
		return err
	}
	return nil
}

func WriteFindingText(w io.Writer, finding model.Finding) error {
	if _, err := fmt.Fprintf(w, "[%s][%.2f] %s:%d %s %s -> %s\n",
		finding.RuleID,
		finding.Score,
		finding.File,
		finding.Line,
		finding.Category,
		finding.Reason,
		finding.Match,
	); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "  %s\n", finding.Excerpt)
	return err
}

func WriteScanCSVSummary(w io.Writer, result model.ScanResult) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	if err := writer.Write([]string{
		"rule_id",
		"category",
		"severity",
		"reason",
		"count",
		"file_count",
		"max_score",
		"sample_file",
		"sample_line",
		"sample_match",
		"sample_excerpt",
	}); err != nil {
		return err
	}

	type groupKey struct {
		RuleID   string
		Category string
		Severity string
		Reason   string
	}
	type groupSummary struct {
		key      groupKey
		count    int
		maxScore float64
		files    map[string]struct{}
		sample   model.Finding
	}

	groups := make(map[groupKey]*groupSummary)
	for _, finding := range result.Findings {
		key := groupKey{
			RuleID:   finding.RuleID,
			Category: finding.Category,
			Severity: finding.Severity,
			Reason:   finding.Reason,
		}
		group := groups[key]
		if group == nil {
			group = &groupSummary{
				key:      key,
				maxScore: finding.Score,
				files:    map[string]struct{}{finding.File: {}},
				sample:   finding,
			}
			groups[key] = group
		}
		group.count++
		group.files[finding.File] = struct{}{}
		if finding.Score > group.maxScore {
			group.maxScore = finding.Score
		}
	}

	summaries := make([]*groupSummary, 0, len(groups))
	for _, group := range groups {
		summaries = append(summaries, group)
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		if summaries[i].count != summaries[j].count {
			return summaries[i].count > summaries[j].count
		}
		if summaries[i].key.Category != summaries[j].key.Category {
			return summaries[i].key.Category < summaries[j].key.Category
		}
		if summaries[i].key.RuleID != summaries[j].key.RuleID {
			return summaries[i].key.RuleID < summaries[j].key.RuleID
		}
		return summaries[i].key.Reason < summaries[j].key.Reason
	})

	for _, summary := range summaries {
		if err := writer.Write([]string{
			summary.key.RuleID,
			summary.key.Category,
			summary.key.Severity,
			summary.key.Reason,
			fmt.Sprintf("%d", summary.count),
			fmt.Sprintf("%d", len(summary.files)),
			fmt.Sprintf("%.2f", summary.maxScore),
			summary.sample.File,
			fmt.Sprintf("%d", summary.sample.Line),
			summary.sample.Match,
			summary.sample.Excerpt,
		}); err != nil {
			return err
		}
	}

	return writer.Error()
}

func WriteValidationText(w io.Writer, result model.ValidationReport) error {
	if _, err := fmt.Fprintf(w, "Dataset: %s\nPrecision: %.2f Recall: %.2f FDR: %.2f TP=%d FP=%d FN=%d\n",
		result.Dataset,
		result.Precision,
		result.Recall,
		result.FalseDiscovery,
		result.TruePositives,
		result.FalsePositives,
		result.FalseNegatives,
	); err != nil {
		return err
	}
	if len(result.Unexpected) > 0 {
		if _, err := fmt.Fprintln(w, "Unexpected:"); err != nil {
			return err
		}
		for _, item := range result.Unexpected {
			if _, err := fmt.Fprintf(w, "  %s %s %s (%s)\n", item.File, item.RuleID, item.Match, item.Reason); err != nil {
				return err
			}
		}
	}
	if len(result.Missed) > 0 {
		if _, err := fmt.Fprintln(w, "Missed:"); err != nil {
			return err
		}
		for _, item := range result.Missed {
			if _, err := fmt.Fprintf(w, "  %s %s %s\n", item.File, item.RuleID, item.Match); err != nil {
				return err
			}
		}
	}
	if len(result.GroupStats) > 0 {
		if _, err := fmt.Fprintln(w, "Groups:"); err != nil {
			return err
		}
		for _, stat := range result.GroupStats {
			if _, err := fmt.Fprintf(w, "  %s P=%.2f R=%.2f FDR=%.2f TP=%d FP=%d FN=%d\n",
				stat.Group,
				stat.Precision,
				stat.Recall,
				stat.FalseDiscovery,
				stat.TruePositives,
				stat.FalsePositives,
				stat.FalseNegatives,
			); err != nil {
				return err
			}
		}
	}
	return nil
}
