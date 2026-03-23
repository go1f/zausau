package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jyufu/sensitive-info-scan/internal/config"
	"github.com/jyufu/sensitive-info-scan/internal/learn"
	"github.com/jyufu/sensitive-info-scan/internal/model"
	"github.com/jyufu/sensitive-info-scan/internal/report"
	"github.com/jyufu/sensitive-info-scan/internal/rules"
	"github.com/jyufu/sensitive-info-scan/internal/scan"
)

const defaultConfigPath = "configs/default-rules.json"
const defaultPromptPath = "skills/sensitive-rule-evolver/references/prompt-template.md"
const defaultReviewPromptPath = "skills/sensitive-rule-evolver/references/review-template.md"
const defaultRegressionManifestPath = "testdata/datasets/regression-manifest.json"

func Run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "validate":
		return runValidate(args[1:])
	case "learn":
		return runLearn(args[1:])
	default:
		return usage()
	}
}

func usage() error {
	return fmt.Errorf("usage: senscan <scan|validate|learn> [flags]")
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to rule config")
	format := fs.String("format", "text", "output format: text or json")
	minScore := fs.Float64("min-score", 0, "override minimum score")
	workers := fs.Int("workers", 0, "override worker count")
	maxFileSize := fs.Int64("max-file-size", 0, "override max file size")
	if err := fs.Parse(args); err != nil {
		return err
	}
	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	cfg, engine, err := loadEngine(*configPath, *workers, *maxFileSize, *minScore)
	if err != nil {
		return err
	}
	_ = cfg

	scanner := scan.NewScanner(cfg, engine)
	result, err := scanner.ScanPath(target)
	if err != nil {
		return err
	}

	switch strings.ToLower(*format) {
	case "json":
		return report.WriteJSON(os.Stdout, result)
	default:
		return report.WriteScanText(os.Stdout, result)
	}
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to rule config")
	manifestPath := fs.String("manifest", "testdata/samples/manifest.json", "path to validation manifest")
	format := fs.String("format", "text", "output format: text or json")
	minScore := fs.Float64("min-score", 0, "override minimum score")
	workers := fs.Int("workers", 0, "override worker count")
	maxFileSize := fs.Int64("max-file-size", 0, "override max file size")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, engine, err := loadEngine(*configPath, *workers, *maxFileSize, *minScore)
	if err != nil {
		return err
	}

	manifest, err := loadManifest(*manifestPath)
	if err != nil {
		return err
	}

	scanner := scan.NewScanner(cfg, engine)
	validation, err := validateManifest(scanner, manifest)
	if err != nil {
		return err
	}

	switch strings.ToLower(*format) {
	case "json":
		return report.WriteJSON(os.Stdout, validation)
	default:
		return report.WriteValidationText(os.Stdout, validation)
	}
}

func runLearn(args []string) error {
	fs := flag.NewFlagSet("learn", flag.ContinueOnError)
	configPath := fs.String("config", defaultConfigPath, "path to rule config")
	manifestPath := fs.String("manifest", defaultRegressionManifestPath, "path to validation manifest")
	endpoint := fs.String("endpoint", "http://127.0.0.1:4141/v1/chat/completions", "copilot api chat endpoint")
	modelName := fs.String("model", "gpt-5.4", "copilot api model")
	promptPath := fs.String("prompt", defaultPromptPath, "skill prompt template")
	reviewPromptPath := fs.String("review-prompt", defaultReviewPromptPath, "rule review prompt template")
	outputPath := fs.String("out", "artifacts/rule-suggestions.json", "output path")
	reviewOutputPath := fs.String("review-out", "artifacts/rule-review.json", "review output path")
	minPrecision := fs.Float64("min-precision", 0.95, "minimum precision gate for proposal review")
	minRecall := fs.Float64("min-recall", 0.90, "minimum recall gate for proposal review")
	maxFalseDiscovery := fs.Float64("max-fdr", 0.05, "maximum false discovery rate gate for proposal review")
	minScore := fs.Float64("min-score", 0, "override minimum score")
	workers := fs.Int("workers", 0, "override worker count")
	maxFileSize := fs.Int64("max-file-size", 0, "override max file size")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, engine, err := loadEngine(*configPath, *workers, *maxFileSize, *minScore)
	if err != nil {
		return err
	}
	manifest, err := loadManifest(*manifestPath)
	if err != nil {
		return err
	}
	scanner := scan.NewScanner(cfg, engine)
	validation, err := validateManifest(scanner, manifest)
	if err != nil {
		return err
	}

	client := learn.NewClient(*endpoint, *modelName)
	suggestion, err := client.Suggest(context.Background(), cfg, validation, *promptPath)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(*outputPath), 0o755); err != nil {
		return err
	}
	file, err := os.Create(*outputPath)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := report.WriteJSON(file, suggestion); err != nil {
		return err
	}

	staticFindings := learn.StaticReviewSuggestion(suggestion)
	staticFindings = append(staticFindings, learn.CompileReviewSuggestion(suggestion)...)
	simulatedValidation := model.ValidationReport{Dataset: manifest.Dataset}
	modelReview := model.ModelReview{
		Summary:  "model reviewer skipped",
		Approved: false,
	}
	simulationSuggestion := learn.SanitizedSuggestionForSimulation(suggestion)
	mergedCfg := learn.MergeSuggestion(cfg, simulationSuggestion)
	mergedEngine, err := rules.NewEngine(mergedCfg)
	if err != nil {
		staticFindings = append(staticFindings, model.RuleReviewFinding{
			Severity: "critical",
			Source:   "static",
			Title:    "Merged rule config does not compile",
			Detail:   err.Error(),
		})
		modelReview.Summary = "model reviewer skipped because merged rules did not compile"
	} else {
		simulatedValidation, err = validateManifest(scan.NewScanner(mergedCfg, mergedEngine), manifest)
		if err != nil {
			return err
		}
		modelReview, err = client.ReviewSuggestion(context.Background(), cfg, suggestion, simulatedValidation, staticFindings, *reviewPromptPath)
		if err != nil {
			modelReview = model.ModelReview{
				Summary:  "model reviewer failed",
				Approved: false,
				Findings: []model.RuleReviewFinding{
					{
						Severity: "high",
						Source:   "model-review",
						Title:    "Model reviewer failed",
						Detail:   err.Error(),
					},
				},
			}
		}
	}

	reviewReport := learn.BuildReviewReport(model.ReviewThresholds{
		MinPrecision:      *minPrecision,
		MinRecall:         *minRecall,
		MaxFalseDiscovery: *maxFalseDiscovery,
	}, staticFindings, modelReview, simulatedValidation)

	if err := os.MkdirAll(filepath.Dir(*reviewOutputPath), 0o755); err != nil {
		return err
	}
	reviewFile, err := os.Create(*reviewOutputPath)
	if err != nil {
		return err
	}
	defer reviewFile.Close()
	return report.WriteJSON(reviewFile, reviewReport)
}

func loadEngine(configPath string, workers int, maxFileSize int64, minScore float64) (model.Config, *rules.Engine, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return cfg, nil, err
	}
	if workers > 0 {
		cfg.Workers = workers
	}
	if maxFileSize > 0 {
		cfg.MaxFileSize = maxFileSize
	}
	if minScore > 0 {
		cfg.DefaultMinScore = minScore
	}
	engine, err := rules.NewEngine(cfg)
	if err != nil {
		return cfg, nil, err
	}
	return cfg, engine, nil
}

func loadManifest(path string) (model.ValidationManifest, error) {
	var manifest model.ValidationManifest
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest, err
	}
	if err := jsonUnmarshal(data, &manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func validateManifest(scanner *scan.Scanner, manifest model.ValidationManifest) (model.ValidationReport, error) {
	report := model.ValidationReport{Dataset: manifest.Dataset}
	groupStats := make(map[string]*model.ValidationGroupStat)
	for _, testCase := range manifest.Cases {
		groupName := normalizeCaseGroup(testCase)
		stat := groupStats[groupName]
		if stat == nil {
			stat = &model.ValidationGroupStat{Group: groupName}
			groupStats[groupName] = stat
		}
		result, err := scanner.ScanPath(testCase.File)
		if err != nil {
			return report, err
		}
		matched := make([]bool, len(result.Findings))
		for _, expected := range testCase.Expected {
			found := false
			for i, finding := range result.Findings {
				if finding.RuleID != expected.RuleID {
					continue
				}
				if expected.Category != "" && finding.Category != expected.Category {
					continue
				}
				if expected.MatchContains != "" && !strings.Contains(finding.Match, expected.MatchContains) {
					continue
				}
				matched[i] = true
				found = true
				report.TruePositives++
				stat.TruePositives++
				break
			}
			if !found {
				report.FalseNegatives++
				stat.FalseNegatives++
				report.Missed = append(report.Missed, model.ValidationMismatch{
					File:     testCase.File,
					RuleID:   expected.RuleID,
					Category: expected.Category,
					Match:    expected.MatchContains,
				})
			}
		}
		for i, finding := range result.Findings {
			if matched[i] {
				continue
			}
			report.FalsePositives++
			stat.FalsePositives++
			report.Unexpected = append(report.Unexpected, model.ValidationMismatch{
				File:     finding.File,
				RuleID:   finding.RuleID,
				Category: finding.Category,
				Match:    finding.Redacted,
				Reason:   finding.Reason,
				Score:    finding.Score,
			})
		}
	}
	report.Precision = ratio(report.TruePositives, report.TruePositives+report.FalsePositives)
	report.Recall = ratio(report.TruePositives, report.TruePositives+report.FalseNegatives)
	report.FalseDiscovery = ratio(report.FalsePositives, report.TruePositives+report.FalsePositives)
	for _, stat := range groupStats {
		stat.Precision = ratio(stat.TruePositives, stat.TruePositives+stat.FalsePositives)
		stat.Recall = ratio(stat.TruePositives, stat.TruePositives+stat.FalseNegatives)
		stat.FalseDiscovery = ratio(stat.FalsePositives, stat.TruePositives+stat.FalsePositives)
		report.GroupStats = append(report.GroupStats, *stat)
	}
	sort.SliceStable(report.GroupStats, func(i, j int) bool {
		return report.GroupStats[i].Group < report.GroupStats[j].Group
	})
	return report, nil
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func jsonUnmarshal(data []byte, out any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func normalizeCaseGroup(testCase model.ValidationCase) string {
	if strings.TrimSpace(testCase.Group) != "" {
		return testCase.Group
	}
	path := filepath.ToSlash(strings.ToLower(testCase.File))
	switch {
	case strings.Contains(path, "/negative/"):
		return "negative"
	case strings.Contains(path, "/public/"):
		return "public-positive"
	case strings.Contains(path, "/samples/"):
		return "built-in-positive"
	default:
		return "ungrouped"
	}
}
