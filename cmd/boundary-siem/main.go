// Package main provides the TUI entry point for Boundary-SIEM
package main

import (
	"flag"
	"fmt"
	"os"

	"boundary-siem/internal/tui"
)

var (
	version = "dev"
)

func main() {
	var (
		showVersion bool
		serverURL   string
	)

	flag.BoolVar(&showVersion, "version", false, "Show version and exit")
	flag.BoolVar(&showVersion, "v", false, "Show version and exit (shorthand)")
	flag.StringVar(&serverURL, "server", "http://localhost:8080", "Boundary-SIEM server URL")
	flag.StringVar(&serverURL, "s", "http://localhost:8080", "Boundary-SIEM server URL (shorthand)")
	flag.Parse()

	if showVersion {
		fmt.Printf("boundary-siem %s\n", version)
		os.Exit(0)
	}

	// Print startup banner
	fmt.Println("Starting Boundary-SIEM TUI...")
	fmt.Printf("Connecting to: %s\n", serverURL)

	if err := tui.Run(serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
