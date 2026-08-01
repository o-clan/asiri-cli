package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

const (
	progressStartDelay = 180 * time.Millisecond
	progressFrameDelay = 80 * time.Millisecond
	progressClearLine  = "\r\x1b[2K"
)

var progressFrames = [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type terminalProgress struct {
	writer   io.Writer
	delay    time.Duration
	interval time.Duration
	done     chan struct{}
	stopOnce sync.Once
	wait     sync.WaitGroup
	mu       sync.RWMutex
	label    string
	rendered bool
}

func (a App) withProgress(label string, operation func() error) error {
	progress := newTerminalProgress(a.Err, terminalProgressEnabled(a.Err), label, progressStartDelay, progressFrameDelay)
	defer progress.Stop()
	return operation()
}

func newTerminalProgress(writer io.Writer, enabled bool, label string, delay, interval time.Duration) *terminalProgress {
	progress := &terminalProgress{writer: writer, delay: delay, interval: interval, done: make(chan struct{}), label: label}
	if !enabled {
		close(progress.done)
		return progress
	}
	progress.wait.Add(1)
	go progress.animate()
	return progress
}

func (progress *terminalProgress) Update(label string) {
	progress.mu.Lock()
	progress.label = label
	progress.mu.Unlock()
}

func (progress *terminalProgress) Stop() {
	progress.stopOnce.Do(func() {
		select {
		case <-progress.done:
		default:
			close(progress.done)
		}
	})
	progress.wait.Wait()
}

func (progress *terminalProgress) animate() {
	defer progress.wait.Done()
	timer := time.NewTimer(progress.delay)
	defer timer.Stop()
	select {
	case <-progress.done:
		return
	case <-timer.C:
	}

	frame := 0
	progress.render(progressFrames[frame])
	ticker := time.NewTicker(progress.interval)
	defer ticker.Stop()
	for {
		select {
		case <-progress.done:
			progress.clear()
			return
		case <-ticker.C:
			frame = (frame + 1) % len(progressFrames)
			progress.render(progressFrames[frame])
		}
	}
}

func (progress *terminalProgress) render(frame string) {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	_, _ = fmt.Fprintf(progress.writer, "%s%s %s", progressClearLine, frame, progress.label)
	progress.rendered = true
}

func (progress *terminalProgress) clear() {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	if progress.rendered {
		_, _ = io.WriteString(progress.writer, progressClearLine)
	}
}

func terminalProgressEnabled(writer io.Writer) bool {
	if envEnabled("ASIRI_NO_PROGRESS") || envEnabled("CI") || strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return false
	}
	file, ok := writer.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func envEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
