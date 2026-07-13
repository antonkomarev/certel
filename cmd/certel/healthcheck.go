package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/antonkomarev/certel/internal/config"
)

// runHealthcheckCmd parses the healthcheck flags and probes the local monitor.
func runHealthcheckCmd(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to the YAML configuration file (read for the listen address)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: certel healthcheck [-config config.yaml]

Probe a running monitor's /healthz endpoint and exit 0 (healthy) or 1
(unhealthy). Reads only the listen address from the config.

flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)
	return runHealthcheck(*configPath)
}

// runHealthcheck GETs the local /healthz endpoint and returns a process exit
// code (0 healthy, 1 otherwise). It reads only the listen address from the
// config — not the full validated Load — so the probe works from environments
// that lack the notifier secrets referenced by ${env.VAR} headers, and so a
// container HEALTHCHECK can call the binary itself, with no curl or wget in
// the image. The listen host is normalized to loopback because the check
// always runs inside the same network namespace.
func runHealthcheck(configPath string) int {
	listen, err := config.ListenAddress(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: config error:", err)
		return 1
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: invalid listen address:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port) + "/healthz"
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == http.StatusOK {
		return 0
	}
	fmt.Fprintf(os.Stderr, "healthcheck: /healthz returned %s\n", resp.Status)
	return 1
}
