// Package main provides a CLI tool for validating Boundary-SIEM YAML rules.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"boundary-siem/internal/correlation"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "validate":
		runValidateCmd(os.Args[2:])
	case "list":
		runListCmd(os.Args[2:])
	case "-version", "--version", "-v":
		fmt.Printf("siem-rules %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: siem-rules <command> [flags] [args]\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  validate  Validate YAML rule files or directories\n")
	fmt.Fprintf(os.Stderr, "  list      List rules found in files or directories\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	fmt.Fprintf(os.Stderr, "  -version  Show version and exit\n")
}

func runValidateCmd(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	verbose := fs.Bool("verbose", false, "Show detailed rule information")
	fs.Parse(args)

	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintf(os.Stderr, "Error: at least one path is required\n")
		fmt.Fprintf(os.Stderr, "Usage: siem-rules validate [--verbose] <path> [<path>...]\n")
		os.Exit(1)
	}

	os.Exit(runValidate(paths, *verbose))
}

func runListCmd(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	fs.Parse(args)

	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"rules"}
	}

	os.Exit(runList(paths))
}

func runValidate(paths []string, verbose bool) int {
	var totalFiles, validFiles, invalidFiles int

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s: %v\n", path, err)
			invalidFiles++
			continue
		}

		if info.IsDir() {
			files, err := collectYAMLFiles(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading directory %s: %v\n", path, err)
				invalidFiles++
				continue
			}
			for _, f := range files {
				totalFiles++
				if validateFile(f, verbose) {
					validFiles++
				} else {
					invalidFiles++
				}
			}
		} else {
			totalFiles++
			if validateFile(path, verbose) {
				validFiles++
			} else {
				invalidFiles++
			}
		}
	}

	fmt.Printf("\nResults: %d files checked, %d valid, %d invalid\n", totalFiles, validFiles, invalidFiles)

	if invalidFiles > 0 {
		return 1
	}
	return 0
}

func validateFile(path string, verbose bool) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("  FAIL  %s: %v\n", path, err)
		return false
	}

	rules, err := correlation.ParseRules(data)
	if err != nil {
		fmt.Printf("  FAIL  %s: %v\n", path, err)
		return false
	}

	fmt.Printf("  OK    %s (%d rule(s))\n", path, len(rules))

	if verbose {
		for _, rule := range rules {
			fmt.Printf("        - [%s] %s (type=%s, severity=%d)\n",
				rule.ID, rule.Name, rule.Type, rule.Severity)
			if len(rule.Tags) > 0 {
				fmt.Printf("          tags: %s\n", strings.Join(rule.Tags, ", "))
			}
			if rule.MITRE != nil {
				fmt.Printf("          mitre: %s / %s\n", rule.MITRE.TacticID, rule.MITRE.TechniqueID)
			}
			if len(rule.DependsOn) > 0 {
				fmt.Printf("          depends_on: %s\n", strings.Join(rule.DependsOn, ", "))
			}
		}
	}

	return true
}

func runList(paths []string) int {
	for _, path := range paths {
		files, err := collectYAMLFiles(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", path, err)
			continue
		}

		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			rules, err := correlation.ParseRules(data)
			if err != nil {
				continue
			}
			for _, rule := range rules {
				fmt.Printf("%-40s  %-12s  sev=%-2d  %s\n",
					rule.ID, rule.Type, rule.Severity, rule.Name)
			}
		}
	}
	return 0
}

func collectYAMLFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
