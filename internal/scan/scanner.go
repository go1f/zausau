package scan

import (
	"bufio"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/jyufu/sensitive-info-scan/internal/model"
	"github.com/jyufu/sensitive-info-scan/internal/rules"
)

type Scanner struct {
	cfg    model.Config
	engine *rules.Engine
}

func NewScanner(cfg model.Config, engine *rules.Engine) *Scanner {
	return &Scanner{cfg: cfg, engine: engine}
}

func (s *Scanner) ScanPath(root string) (model.ScanResult, error) {
	type fileJob struct {
		path string
		size int64
	}

	jobs := make(chan fileJob, s.cfg.Workers*2)
	findingsCh := make(chan []model.Finding, s.cfg.Workers)
	statsCh := make(chan model.ScanStats, s.cfg.Workers)

	var workers sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				findings, stats := s.scanFile(job.path, job.size)
				findingsCh <- findings
				statsCh <- stats
			}
		}()
	}

	var walkErr error
	var skipped int
	go func() {
		defer close(jobs)
		walkErr = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if shouldIgnorePath(path, s.cfg.IgnorePaths) && path != root {
					return filepath.SkipDir
				}
				return nil
			}
			if shouldIgnorePath(path, s.cfg.IgnorePaths) || shouldIgnoreExt(path, s.cfg.IgnoreExts) {
				skipped++
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Size() > s.cfg.MaxFileSize {
				skipped++
				return nil
			}
			jobs <- fileJob{path: path, size: info.Size()}
			return nil
		})
	}()

	go func() {
		workers.Wait()
		close(findingsCh)
		close(statsCh)
	}()

	var result model.ScanResult
	result.Stats.FilesSkipped = skipped
	for statsCh != nil || findingsCh != nil {
		select {
		case findings, ok := <-findingsCh:
			if !ok {
				findingsCh = nil
				continue
			}
			result.Findings = append(result.Findings, findings...)
		case stats, ok := <-statsCh:
			if !ok {
				statsCh = nil
				continue
			}
			result.Stats.FilesScanned += stats.FilesScanned
			result.Stats.FilesSkipped += stats.FilesSkipped
			result.Stats.BytesScanned += stats.BytesScanned
		}
	}

	sort.SliceStable(result.Findings, func(i, j int) bool {
		if result.Findings[i].File == result.Findings[j].File {
			if result.Findings[i].Line == result.Findings[j].Line {
				return result.Findings[i].Column < result.Findings[j].Column
			}
			return result.Findings[i].Line < result.Findings[j].Line
		}
		return result.Findings[i].File < result.Findings[j].File
	})

	return result, walkErr
}

func (s *Scanner) scanFile(path string, size int64) ([]model.Finding, model.ScanStats) {
	file, err := os.Open(path)
	if err != nil {
		return nil, model.ScanStats{FilesSkipped: 1}
	}
	defer file.Close()

	header := make([]byte, 512)
	n, _ := file.Read(header)
	if isBinary(header[:n]) {
		return nil, model.ScanStats{FilesSkipped: 1}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, model.ScanStats{FilesSkipped: 1}
	}

	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 0, 64*1024)
	scanner.Buffer(buffer, 1024*1024)

	lineNo := 0
	var findings []model.Finding
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if shouldSkipLine(line) {
			continue
		}
		findings = append(findings, s.engine.ScanLine(path, lineNo, line)...)
	}
	return findings, model.ScanStats{
		FilesScanned: 1,
		BytesScanned: size,
	}
}

func shouldIgnorePath(path string, tokens []string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, token := range tokens {
		token = strings.ToLower(strings.TrimSpace(token))
		if token != "" && strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func shouldIgnoreExt(path string, exts []string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, item := range exts {
		if ext == strings.ToLower(item) {
			return true
		}
	}
	return false
}

func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return true
	}
	var nonText int
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' {
			continue
		}
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			nonText++
		}
	}
	return nonText > len(data)/10
}

func shouldSkipLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "pragma: allowlist secret") ||
		strings.Contains(lower, "detect-secrets: allowlist secret") ||
		strings.Contains(lower, "gitleaks:allow")
}
