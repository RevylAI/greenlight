package cli

import (
	"fmt"
	"strings"

	"github.com/RevylAI/greenlight/internal/guidelines"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var guidelinesCmd = &cobra.Command{
	Use:     "guidelines",
	Aliases: []string{"gl"},
	Short:   "Browse and search Apple App Store Review Guidelines",
}

var guidelinesSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search guidelines by keyword",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runGuidelinesSearch,
}

var guidelinesShowCmd = &cobra.Command{
	Use:   "show [section]",
	Short: "Show a specific guideline section (e.g. '2.1', '5.1.1')",
	Args:  cobra.ExactArgs(1),
	RunE:  runGuidelinesShow,
}

var guidelinesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all top-level guideline sections",
	RunE:  runGuidelinesList,
}

func init() {
	guidelinesCmd.AddCommand(guidelinesSearchCmd)
	guidelinesCmd.AddCommand(guidelinesShowCmd)
	guidelinesCmd.AddCommand(guidelinesListCmd)
}

func runGuidelinesSearch(cmd *cobra.Command, args []string) error {
	query := strings.Join(args, " ")
	db, err := guidelines.Load()
	if err != nil {
		return fmt.Errorf("failed to load guidelines: %w", err)
	}

	results := db.Search(query)

	purple.Printf("\n  Guidelines matching '%s'\n\n", query)

	if len(results) == 0 {
		dim.Println("  No matching guidelines found.")
		return nil
	}

	for _, g := range results {
		bold := color.New(color.Bold)
		bold.Printf("  %s  ", g.Section)
		fmt.Println(g.Title)
		dim.Printf("  %s\n\n", truncate(g.Content, 120))
	}

	return nil
}

func runGuidelinesShow(cmd *cobra.Command, args []string) error {
	section := args[0]
	db, err := guidelines.Load()
	if err != nil {
		return fmt.Errorf("failed to load guidelines: %w", err)
	}

	g, found := db.Get(section)
	if !found {
		return fmt.Errorf("guideline section '%s' not found", section)
	}

	purple.Printf("\n  Guideline %s\n", g.Section)
	color.New(color.Bold).Printf("  %s\n\n", g.Title)
	fmt.Printf("  %s\n", g.Content)

	if len(g.CommonViolations) > 0 {
		fmt.Println()
		color.New(color.FgYellow).Println("  Common violations:")
		for _, v := range g.CommonViolations {
			fmt.Printf("    • %s\n", v)
		}
	}

	if len(g.Subsections) > 0 {
		fmt.Println()
		dim.Println("  Subsections:")
		for _, s := range g.Subsections {
			fmt.Printf("    %s  %s\n", s.Section, s.Title)
		}
	}

	fmt.Println()
	return nil
}

func runGuidelinesList(cmd *cobra.Command, args []string) error {
	db, err := guidelines.Load()
	if err != nil {
		return fmt.Errorf("failed to load guidelines: %w", err)
	}

	purple.Println("\n  Apple App Store Review Guidelines")

	for _, g := range db.TopLevel() {
		bold := color.New(color.Bold)
		bold.Printf("  %s  ", g.Section)
		fmt.Println(g.Title)
		for _, s := range g.Subsections {
			dim.Printf("      %s  %s\n", s.Section, s.Title)
		}
		fmt.Println()
	}

	return nil
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
