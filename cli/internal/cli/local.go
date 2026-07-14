package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/o-clan/asiri/cli/internal/store"
)

func (a App) local(st *store.FileStore, args []string) int {
	if len(args) == 0 {
		return a.fail(errors.New("local subcommand required"))
	}
	switch args[0] {
	case "wipe":
		return a.localWipe(st, args[1:])
	default:
		return a.fail(fmt.Errorf("unknown local command %q", args[0]))
	}
}

func (a App) localWipe(st *store.FileStore, args []string) int {
	if err := rejectUnknownArgs(args, "--yes"); err != nil {
		return a.fail(err)
	}
	if len(positionalArgs(args)) > 0 {
		return a.fail(errors.New("local wipe accepts only --yes"))
	}
	if err := rejectServiceAccountLocalMutation(st); err != nil {
		return a.fail(err)
	}
	if !hasFlag(args, "--yes") {
		if err := a.confirmLocalWipe(); err != nil {
			return a.fail(err)
		}
	}
	if err := wipeLocalState(st); err != nil {
		return a.fail(err)
	}
	fmt.Fprintln(a.Out, "✓ Local Asiri state wiped")
	return 0
}

func (a App) confirmLocalWipe() error {
	fmt.Fprint(a.Out, "Type wipe local to delete local Asiri state: ")
	reader := bufio.NewReader(a.In)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	if value != "wipe local" {
		return errors.New("confirmation did not match; local state was not wiped")
	}
	return nil
}

func (a App) cache(st *store.FileStore, args []string) int {
	if len(args) == 0 || args[0] != "wipe" {
		return a.fail(errors.New("cache wipe is required"))
	}
	if err := rejectServiceAccountLocalMutation(st); err != nil {
		return a.fail(err)
	}
	if err := wipeLocalState(st); err != nil {
		return a.fail(err)
	}
	fmt.Fprintln(a.Out, "✓ Local Asiri cache wiped")
	return 0
}

func wipeLocalState(st *store.FileStore) error {
	if err := st.DeletePlatformKeys(); err != nil {
		return err
	}
	if err := os.Remove(st.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
