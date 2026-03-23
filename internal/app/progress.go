package app

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jyufu/sensitive-info-scan/internal/scan"
)

type scanProgressReporter struct {
	enabled bool
	events  chan scan.ProgressEvent
	done    chan struct{}
}

type scanProgressState struct {
	start           time.Time
	discoveredFiles int
	discoveredBytes int64
	scannedFiles    int
	skippedFiles    int
	bytesScanned    int64
	findings        int
	currentFile     string
	walkComplete    bool
}

func newScanProgressReporter(stderr *os.File, enabled bool) *scanProgressReporter {
	reporter := &scanProgressReporter{
		enabled: enabled && isTerminal(stderr),
	}
	if !reporter.enabled {
		return reporter
	}
	reporter.events = make(chan scan.ProgressEvent, 1024)
	reporter.done = make(chan struct{})
	go reporter.run(stderr)
	return reporter
}

func (r *scanProgressReporter) Emit(event scan.ProgressEvent) {
	if !r.enabled {
		return
	}
	r.events <- event
}

func (r *scanProgressReporter) Close() {
	if !r.enabled {
		return
	}
	close(r.events)
	<-r.done
}

func (r *scanProgressReporter) run(stderr *os.File) {
	defer close(r.done)

	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()

	state := scanProgressState{start: time.Now()}
	var lastWidth int
	var mu sync.Mutex

	render := func() {
		mu.Lock()
		defer mu.Unlock()

		line := formatProgressLine(state)
		padding := ""
		if len(line) < lastWidth {
			padding = strings.Repeat(" ", lastWidth-len(line))
		}
		fmt.Fprintf(stderr, "\r%s%s", line, padding)
		lastWidth = len(line)
	}

	for {
		select {
		case event, ok := <-r.events:
			if !ok {
				fmt.Fprintf(stderr, "\r%s\r", strings.Repeat(" ", lastWidth))
				return
			}
			state.discoveredFiles += event.DiscoveredFiles
			state.discoveredBytes += event.DiscoveredBytes
			state.scannedFiles += event.ScannedFiles
			state.skippedFiles += event.SkippedFiles
			state.bytesScanned += event.BytesScanned
			state.findings += event.Findings
			state.walkComplete = state.walkComplete || event.WalkComplete
			if strings.TrimSpace(event.CurrentFile) != "" {
				state.currentFile = event.CurrentFile
			}
		case <-ticker.C:
			render()
		}
	}
}

func formatProgressLine(state scanProgressState) string {
	spinChars := []string{"|", "/", "-", `\`}
	elapsed := time.Since(state.start)
	spinner := spinChars[int(elapsed/(120*time.Millisecond))%len(spinChars)]

	totalLabel := fmt.Sprintf("%d+", state.discoveredFiles)
	bytesLabel := fmt.Sprintf("%s+", formatBytes(state.discoveredBytes))
	if state.walkComplete {
		totalLabel = fmt.Sprintf("%d", state.discoveredFiles)
		bytesLabel = formatBytes(state.discoveredBytes)
	}

	rate := formatBytesPerSecond(state.bytesScanned, elapsed)
	current := shortenPath(state.currentFile, 72)

	return fmt.Sprintf(
		"%s scan %d/%s skip %d hit %d data %s/%s rate %s current %s",
		spinner,
		state.scannedFiles,
		totalLabel,
		state.skippedFiles,
		state.findings,
		formatBytes(state.bytesScanned),
		bytesLabel,
		rate,
		current,
	)
}

func isTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func formatBytes(value int64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%dB", value)
	}
	div, exp := int64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(value)/float64(div), "KMGTPE"[exp])
}

func formatBytesPerSecond(bytes int64, elapsed time.Duration) string {
	if elapsed <= 0 {
		return "0B/s"
	}
	perSecond := float64(bytes) / elapsed.Seconds()
	return fmt.Sprintf("%s/s", formatBytes(int64(perSecond)))
}

func shortenPath(path string, limit int) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "-"
	}
	if len(path) <= limit {
		return path
	}
	if limit < 8 {
		return path[:limit]
	}
	return "..." + path[len(path)-limit+3:]
}
