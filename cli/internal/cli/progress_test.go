package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestTerminalProgressDoesNotRenderFastOperations(t *testing.T) {
	var output bytes.Buffer
	progress := newTerminalProgress(&output, true, "Preparing encrypted push", time.Hour, time.Millisecond)
	progress.Stop()
	if output.Len() != 0 {
		t.Fatalf("fast progress should not flicker: %q", output.String())
	}
}

func TestTerminalProgressRendersLatestPhaseAndClearsIt(t *testing.T) {
	var output bytes.Buffer
	progress := newTerminalProgress(&output, true, "Preparing encrypted push", 0, time.Millisecond)
	progress.Update("Committing encrypted push")
	time.Sleep(10 * time.Millisecond)
	progress.Stop()

	rendered := output.String()
	if !strings.Contains(rendered, "Committing encrypted push") {
		t.Fatalf("progress did not render the latest phase: %q", rendered)
	}
	if !strings.HasSuffix(rendered, progressClearLine) {
		t.Fatalf("progress did not clear its terminal line: %q", rendered)
	}
}

func TestTerminalProgressStaysSilentWhenDisabled(t *testing.T) {
	var output bytes.Buffer
	progress := newTerminalProgress(&output, false, "Preparing encrypted push", 0, time.Millisecond)
	progress.Update("Committing encrypted push")
	progress.Stop()
	if output.Len() != 0 {
		t.Fatalf("disabled progress wrote output: %q", output.String())
	}
}

func TestTerminalProgressRequiresAnInteractiveWriter(t *testing.T) {
	var output bytes.Buffer
	if terminalProgressEnabled(&output) {
		t.Fatal("buffered output must not enable terminal animation")
	}
}
