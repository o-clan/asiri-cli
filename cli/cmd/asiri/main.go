package main

import (
	"os"

	"github.com/o-clan/asiri/cli/internal/cli"
)

func main() {
	app := cli.New(os.Stdout, os.Stderr)
	os.Exit(app.Run(os.Args[1:]))
}
