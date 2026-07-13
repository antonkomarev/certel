package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/antonkomarev/certel/internal/config"
)

// runValidateConfig loads and validates a configuration file, including
// compiling every notifier body — the same startup path the monitor runs,
// so "validate-config passed" means "monitor will start". Returns 0 on a
// valid config, 1 on a validation error, 2 on a usage error.
func runValidateConfig(args []string) int {
	fs := flag.NewFlagSet("validate-config", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: certel validate-config [config.yaml]

Validate a configuration file and exit. The path defaults to config.yaml.
`)
	}
	fs.Parse(args)
	if fs.NArg() > 1 {
		fs.Usage()
		return 2
	}
	path := "config.yaml"
	if fs.NArg() == 1 {
		path = fs.Arg(0)
	}

	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "certel validate-config:", err)
		return 1
	}
	if _, err := buildRuntimes(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "certel validate-config:", err)
		return 1
	}
	fmt.Printf("configuration OK: %d target(s), %d notifier(s), interval %s\n",
		len(cfg.Targets), len(cfg.Notifiers), cfg.Probe.CheckInterval.Std())
	return 0
}
