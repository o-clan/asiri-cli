package cli

import (
	"fmt"
	"io"
	"os"

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
	st, err := store.LoadDefault()
	if err != nil {
		return a.fail(err)
	}
	cmd := args[0]
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
	case "grant":
		return a.grant(st, args)
	case "deny":
		return a.deny(st, args)
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

func (a App) fail(err error) int {
	fmt.Fprintf(a.Err, "asiri: %s\n", err)
	return 1
}
