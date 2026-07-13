// Command certel is a TLS certificate monitor. `certel monitor` watches the
// configured endpoints and delivers rendered webhook alerts when a
// certificate is about to expire or is otherwise unhealthy; `certel check`
// probes one target once and prints the result as JSON, touching neither the
// database nor any notifier.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

var version = "dev" // overridden via -ldflags at release build time

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: certel <command> [flags]

commands:
  monitor          watch the configured targets and deliver webhook alerts
  check            probe one target once and print the result as JSON
                   (nothing is persisted, no alert is sent)
  validate-config  validate a configuration file and exit
  healthcheck      probe a running monitor's /healthz and exit 0 (healthy) or 1
  version          print the version
  completion       print a shell completion script (bash, zsh, or fish)

Run "certel <command> -h" for the flags of a command.
`)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "monitor":
		runMonitor(rest)
	case "check":
		os.Exit(runCheck(rest))
	case "validate-config":
		os.Exit(runValidateConfig(rest))
	case "healthcheck":
		os.Exit(runHealthcheckCmd(rest))
	case "completion":
		os.Exit(runCompletion(rest))
	case "version":
		fmt.Println("certel", version)
	case "help", "-h", "-help", "--help":
		usage(os.Stdout)
	default:
		// Pre-subcommand releases took flags directly (certel -config ...);
		// point such invocations at `certel monitor` instead of leaving them
		// with a bare "unknown command".
		if strings.HasPrefix(cmd, "-") {
			fmt.Fprintf(os.Stderr, "certel: flags now belong to a subcommand; did you mean: certel monitor %s\n\n",
				strings.Join(args, " "))
		} else {
			fmt.Fprintf(os.Stderr, "certel: unknown command %q\n\n", cmd)
		}
		usage(os.Stderr)
		os.Exit(2)
	}
}
