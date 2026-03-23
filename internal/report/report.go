package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/jyufu/sensitive-info-scan/internal/model"
)

func WriteJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func WriteScanText(w io.Writer, result model.ScanResult) error {
	if _, err := fmt.Fprintf(w, "Scanned %d files, skipped %d, bytes %d, findings %d\n",
		result.Stats.FilesScanned,
		result.Stats.FilesSkipped,
		result.Stats.BytesScanned,
		len(result.Findings),
	); err != nil {
		return err
	}
	for _, finding := range result.Findings {
		if _, err := fmt.Fprintf(w, "[%s][%.2f] %s:%d %s %s -> %s\n",
			finding.RuleID,
			finding.Score,
			finding.File,
			finding.Line,
			finding.Category,
			finding.Reason,
			finding.Redacted,
		); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  %s\n", finding.Excerpt); err != nil {
			return err
		}
	}
	return nil
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
