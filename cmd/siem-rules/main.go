// Package main provides a CLI tool for validating Boundary-SIEM YAML rules.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"boundary-siem/internal/correlation"
	detectionrules "boundary-siem/internal/detection/rules"
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
	fmt.Fprintf(os.Stderr, "A rule file may hold one rule, a list of rules, or several YAML\n")
	fmt.Fprintf(os.Stderr, "documents separated by '---'. depends_on and kill-chain stages must name\n")
	fmt.Fprintf(os.Stderr, "a built-in rule or a rule in one of the given files.\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	fmt.Fprintf(os.Stderr, "  -version  Show version and exit\n")
}

func runValidateCmd(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	verbose := fs.Bool("verbose", false, "Show detailed rule information")
	parseFlags(fs, args)

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
	parseFlags(fs, args)

	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"rules"}
	}

	os.Exit(runList(paths))
}

// parseFlags parses args into fs, exiting with the flag package's usage-error
// status (2) if parsing fails.
func parseFlags(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}

// builtinRuleIDs returns the IDs of the rules siem-ingest registers itself:
// the detection rules and the kill chains. Rule files may depend on them.
func builtinRuleIDs() map[string]bool {
	ids := make(map[string]bool)
	for _, r := range detectionrules.GetAllRules() {
		ids[r.ID] = true
	}
	for _, c := range correlation.BuiltinChains() {
		ids[c.ID] = true
	}
	return ids
}

// ruleFile is one rule file and the outcome of loading it.
type ruleFile struct {
	path  string
	rules []*correlation.Rule
	err   error
}

// loadRuleFile reads and parses (and validates) every rule in path.
func loadRuleFile(path string) ruleFile {
	// Paths are supplied by the user invoking the CLI, who may validate any
	// file they can read.
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return ruleFile{path: path, err: err}
	}
	rules, err := correlation.ParseRules(data)
	return ruleFile{path: path, rules: rules, err: err}
}

// expandPaths turns the command-line paths into rule files: a file is taken
// as is, a directory contributes its .yaml/.yml files. Paths that cannot be
// read are reported to errOut and counted in failures.
func expandPaths(errOut io.Writer, paths []string) (files []string, failures int) {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(errOut, "Error: %s: %v\n", path, err)
			failures++
			continue
		}
		if !info.IsDir() {
			files = append(files, path)
			continue
		}
		found, err := collectYAMLFiles(path)
		if err != nil {
			fmt.Fprintf(errOut, "Error: %s: %v\n", path, err)
			failures++
			continue
		}
		files = append(files, found...)
	}
	return files, failures
}

// indent prefixes every line of err's message after the first.
func indent(err error, prefix string) string {
	return strings.ReplaceAll(err.Error(), "\n", "\n"+prefix)
}

func runValidate(paths []string, verbose bool) int {
	return validatePaths(os.Stdout, os.Stderr, paths, verbose)
}

// validatePaths validates every rule file under paths: each rule on its own
// (see correlation.Rule.Validate), rule IDs unique across the files, and
// every depends_on / kill-chain stage naming a known rule. It returns the
// process exit code.
func validatePaths(out, errOut io.Writer, paths []string, verbose bool) int {
	files, invalidFiles := expandPaths(errOut, paths)

	loaded := make([]ruleFile, 0, len(files))
	for _, f := range files {
		loaded = append(loaded, loadRuleFile(f))
	}

	// Cross-file checks: duplicate IDs and dangling references.
	builtin := builtinRuleIDs()
	known := make(map[string]bool, len(builtin))
	for id := range builtin {
		known[id] = true
	}
	definedIn := make(map[string]string)
	for i := range loaded {
		f := &loaded[i]
		for _, r := range f.rules {
			if prev, dup := definedIn[r.ID]; dup {
				f.err = errors.Join(f.err, fmt.Errorf("rule %s is also defined in %s", r.ID, prev))
				continue
			}
			definedIn[r.ID] = f.path
			known[r.ID] = true
		}
	}
	for i := range loaded {
		f := &loaded[i]
		if f.err == nil {
			f.err = correlation.ValidateDependencies(f.rules, known)
		}
	}

	var validFiles, ruleCount int
	for _, f := range loaded {
		if f.err != nil {
			fmt.Fprintf(out, "  FAIL  %s: %s\n", f.path, indent(f.err, "          "))
			invalidFiles++
			continue
		}
		validFiles++
		ruleCount += len(f.rules)
		fmt.Fprintf(out, "  OK    %s (%d rule(s))\n", f.path, len(f.rules))
		for _, rule := range f.rules {
			if builtin[rule.ID] {
				fmt.Fprintf(out, "        warning: %s replaces the built-in rule with the same ID\n", rule.ID)
			}
			if verbose {
				printRuleDetails(out, rule)
			}
		}
	}

	fmt.Fprintf(out, "\nResults: %d files checked, %d valid, %d invalid (%d valid rules)\n",
		len(loaded), validFiles, invalidFiles, ruleCount)

	if invalidFiles > 0 {
		return 1
	}
	return 0
}

func printRuleDetails(out io.Writer, rule *correlation.Rule) {
	fmt.Fprintf(out, "        - [%s] %s (type=%s, severity=%d, window=%s)\n",
		rule.ID, rule.Name, rule.Type, rule.Severity, rule.Window)
	if len(rule.Tags) > 0 {
		fmt.Fprintf(out, "          tags: %s\n", strings.Join(rule.Tags, ", "))
	}
	if rule.MITRE != nil {
		fmt.Fprintf(out, "          mitre: %s / %s\n", rule.MITRE.TacticID, rule.MITRE.TechniqueID)
	}
	if len(rule.DependsOn) > 0 {
		fmt.Fprintf(out, "          depends_on: %s\n", strings.Join(rule.DependsOn, ", "))
	}
}

func runList(paths []string) int {
	return listPaths(os.Stdout, os.Stderr, paths)
}

// listPaths prints every rule found under paths. Files or paths that cannot
// be loaded are reported to errOut and make the exit code non-zero.
func listPaths(out, errOut io.Writer, paths []string) int {
	files, failures := expandPaths(errOut, paths)
	for _, path := range files {
		f := loadRuleFile(path)
		if f.err != nil {
			fmt.Fprintf(errOut, "Error: %s: %s\n", f.path, indent(f.err, "  "))
			failures++
			continue
		}
		for _, rule := range f.rules {
			fmt.Fprintf(out, "%-40s  %-12s  sev=%-2d  %s\n",
				rule.ID, rule.Type, rule.Severity, rule.Name)
		}
	}
	if failures > 0 {
		fmt.Fprintf(errOut, "%d file(s) or path(s) could not be loaded\n", failures)
		return 1
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
