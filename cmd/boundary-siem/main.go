// Package main provides the TUI entry point for Boundary-SIEM
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"

	"boundary-siem/internal/tui"
	"boundary-siem/internal/tui/api"
)

var (
	version = "dev"
)

const defaultServerURL = "http://localhost:8080"

// notTheServer explains arguments meant for the SIEM service.
const notTheServer = "boundary-siem is the terminal dashboard and connects to a running server (-server); " +
	"the SIEM service is siem-ingest (siem-ingest -config <file>, siem-ingest health)"

// options holds the parsed command line configuration.
type options struct {
	showVersion  bool
	serverURL    string
	apiKey       string
	apiKeyHeader string
}

// parseFlags parses args, falling back to SIEM_API_KEY and
// SIEM_API_KEY_HEADER from getenv. The key is never used as a flag default
// so that -h does not print it.
func parseFlags(args []string, getenv func(string) string, stderr io.Writer) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("boundary-siem", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.BoolVar(&o.showVersion, "version", false, "Show version and exit")
	fs.BoolVar(&o.showVersion, "v", false, "Show version and exit (shorthand)")
	fs.StringVar(&o.serverURL, "server", defaultServerURL, "Boundary-SIEM server URL")
	fs.StringVar(&o.serverURL, "s", defaultServerURL, "Boundary-SIEM server URL (shorthand)")
	fs.StringVar(&o.apiKey, "api-key", "",
		"API key for servers with auth enabled (default: $SIEM_API_KEY; prefer the environment variable, flags are visible in the process list)")
	fs.StringVar(&o.apiKeyHeader, "api-key-header", "",
		"Header carrying the API key, matching auth.api_key_header (default: $SIEM_API_KEY_HEADER or "+api.DefaultAuthHeader+")")
	// Deployments that mistook this binary for the service passed it
	// "--config <file>" (and "serve", "health"); it started the TUI, which
	// failed with "could not open a new TTY".
	fs.Func("config", "Not supported: "+notTheServer, func(string) error {
		return errors.New(notTheServer)
	})

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q: %s", fs.Arg(0), notTheServer)
	}

	if o.apiKey == "" {
		o.apiKey = getenv("SIEM_API_KEY")
	}
	if o.apiKeyHeader == "" {
		o.apiKeyHeader = getenv("SIEM_API_KEY_HEADER")
	}
	if o.apiKeyHeader == "" {
		o.apiKeyHeader = api.DefaultAuthHeader
	}

	if o.showVersion {
		return o, nil
	}

	u, err := url.Parse(o.serverURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid -server URL %q: expected http(s)://host[:port]", o.serverURL)
	}
	return o, nil
}

// clientOptions converts the parsed options into API client options.
func clientOptions(o *options) []api.Option {
	if o.apiKey == "" {
		return nil
	}
	return []api.Option{api.WithAPIKey(o.apiKey), api.WithAPIKeyHeader(o.apiKeyHeader)}
}

// insecureKeyWarning returns a warning when an API key would be sent in
// cleartext to a non-loopback host, or "" otherwise.
func insecureKeyWarning(o *options) string {
	if o.apiKey == "" {
		return ""
	}
	u, err := url.Parse(o.serverURL)
	if err != nil || u.Scheme != "http" {
		return ""
	}
	host := u.Hostname()
	if host == "localhost" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return ""
	}
	return fmt.Sprintf("Warning: sending the API key over unencrypted HTTP to %s; use https:// for remote servers", host)
}

func main() {
	opts, err := parseFlags(os.Args[1:], os.Getenv, os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	if opts.showVersion {
		fmt.Printf("boundary-siem %s\n", version)
		os.Exit(0)
	}

	// Print startup banner
	fmt.Println("Starting Boundary-SIEM TUI...")
	fmt.Printf("Connecting to: %s\n", opts.serverURL)
	if opts.apiKey != "" {
		fmt.Printf("Authentication: API key set (header %s)\n", opts.apiKeyHeader)
	} else {
		fmt.Println("Authentication: no API key (set -api-key or SIEM_API_KEY if the server has auth enabled)")
	}
	if warning := insecureKeyWarning(opts); warning != "" {
		fmt.Fprintln(os.Stderr, warning)
	}

	if err := tui.Run(opts.serverURL, clientOptions(opts)...); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
