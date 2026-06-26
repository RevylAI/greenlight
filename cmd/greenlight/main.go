package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/RevylAI/greenlight/internal/cli"
)

var version = "dev"

func main() {
	cli.SetVersion(version)
	if err := cli.Execute(); err != nil {
		// ErrThreshold is the --exit-code signal: a clean non-zero exit, no
		// message (the report was already printed). Everything else is a real
		// error worth showing.
		if !errors.Is(err, cli.ErrThreshold) {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		os.Exit(1)
	}
}
