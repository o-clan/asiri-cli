package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/o-clan/asiri/cli/internal/keystore"
	"github.com/o-clan/asiri/cli/internal/store"
)

type App struct {
	Out io.Writer
	Err io.Writer
	In  io.Reader
}

func New(out, err io.Writer) App {
	return App{Out: out, Err: err, In: os.Stdin}
}

func (a App) Run(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		if len(args) > 1 && args[0] == "help" {
			return a.helpFor(args[1:])
		}
		a.help()
		return 0
	}
	if commandHelpRequested(args) {
		return a.helpFor(commandHelpPath(args))
	}
	if args[0] == "--version" || args[0] == "version" {
		fmt.Fprintf(a.Out, "asiri %s\n", Version)
		return 0
	}
	cmd := args[0]
	var st *store.FileStore
	var err error
	if commandUsesLifecycleStateLock(cmd) {
		var release func() error
		err = a.withProgress("Opening local vault", func() error {
			var loadErr error
			st, release, loadErr = store.LoadDefaultLocked()
			return loadErr
		})
		if err == nil {
			defer release()
		}
	} else {
		st, err = store.LoadDefault()
	}
	if err != nil {
		return a.fail(err)
	}
	args = args[1:]
	switch cmd {
	case "init":
		return a.initLocal(st, args)
	case "setup":
		return a.setup(st, args)
	case "login":
		return a.login(st, args)
	case "logout":
		return a.logout(st, args)
	case "whoami":
		return a.whoami(st, args)
	case "workspace":
		return a.workspace(st, args)
	case "member":
		return a.member(st, args)
	case "service-account":
		return a.serviceAccount(st, args)
	case "push":
		return a.push(st, args)
	case "pull":
		return a.pull(st, args)
	case "rewrap":
		return a.rewrap(st, args)
	case "rekey":
		return a.rekey(st, args)
	case "recovery":
		return a.recovery(st, args)
	case "device":
		return a.device(st, args)
	case "secret":
		return a.secret(st, args)
	case "local":
		return a.local(st, args)
	case "add":
		return a.add(st, args)
	case "get":
		return a.get(st, args)
	case "list":
		return a.list(st, args)
	case "rotate":
		return a.rotate(st, args)
	case "rm":
		return a.remove(st, args)
	case "policy":
		return a.policy(st, args)
	case "run":
		return a.run(st, args)
	case "env":
		return a.env(st, args)
	case "mount":
		return a.mount(st, args)
	case "broker":
		return a.broker(st, args)
	case "audit":
		return a.audit(st, args)
	case "cache":
		return a.cache(st, args)
	default:
		return a.fail(fmt.Errorf("unknown command %q", cmd))
	}
}

func commandUsesLifecycleStateLock(command string) bool {
	switch command {
	case "init", "login", "logout", "workspace", "member", "service-account", "push", "pull", "rewrap", "rekey", "recovery", "device", "secret", "local", "add", "rotate", "rm", "cache":
		return true
	default:
		return false
	}
}

func (a App) fail(err error) int {
	if errors.Is(err, keystore.ErrPlatformAuthentication) {
		writeRemoteImportDetails(a.Err, err)
		fmt.Fprintln(a.Err, "asiri: macOS denied access to the login Keychain.")
		fmt.Fprintln(a.Err, "\nThis can happen when macOS leaves the Keychain in a stale state.")
		writeKeychainRecovery(a.Err)
		return 1
	}
	if errors.Is(err, keystore.ErrPlatformTimeout) {
		writeRemoteImportDetails(a.Err, err)
		fmt.Fprintln(a.Err, "asiri: macOS Keychain did not respond in time.")
		fmt.Fprintln(a.Err, "\nAsiri could not confirm that the Keychain operation completed.")
		writeKeychainRecovery(a.Err)
		return 1
	}
	fmt.Fprintf(a.Err, "asiri: %s\n", err)
	return 1
}

func writeRemoteImportDetails(out io.Writer, err error) {
	var conflictErr *store.RemoteImportConflictError
	if errors.As(err, &conflictErr) {
		fmt.Fprintf(out, "asiri: %s\n\n", conflictErr)
		return
	}
	var partialErr *store.RemoteImportPartialError
	if errors.As(err, &partialErr) {
		fmt.Fprintf(out, "asiri: %s\n\n", partialErr)
	}
}

func writeKeychainRecovery(out io.Writer) {
	fmt.Fprintln(out, "\nRefresh the Keychain:")
	fmt.Fprintln(out, "  security lock-keychain")
	fmt.Fprintln(out, "  security unlock-keychain")
	fmt.Fprintln(out, "\nEnter your Mac password when prompted, then retry.")
}
