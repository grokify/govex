package vulnreport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/grokify/govex"
)

// CmdReport is the default subcommand name.
const CmdReport = "report"

// CmdReportOptions holds the report subcommand flags.
type CmdReportOptions struct {
	InputFilename  string
	OutputFilename string
	Title          string
	Subtitle       string
	Organization   string
	Author         string
	Classification string
	Summary        string
	Columns        string // "default" or "residual"
}

// CmdReportCobra returns a Cobra command that generates a Markdown, HTML,
// PDF, or JSON report from a GoVEX JSON file. The input may be either a
// VulnerabilitiesSet JSON file or a vulnreport Report JSON file; the output
// format is inferred from the output filename extension.
func CmdReportCobra(cmdName string) *cobra.Command {
	cmdName = strings.TrimSpace(cmdName)
	if cmdName == "" {
		cmdName = CmdReport
	}
	opts := &CmdReportOptions{}
	c := &cobra.Command{
		Use:   cmdName,
		Short: "Generate a vulnerability report",
		Long:  `Generate a Markdown, HTML, PDF, or JSON vulnerability report from a GoVEX JSON file. The output format is inferred from the output file extension (.md, .html, .pdf, .json).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	flags := c.Flags()
	flags.StringVarP(&opts.InputFilename, "input", "i", "", "input JSON file: VulnerabilitiesSet or Report (required)")
	flags.StringVarP(&opts.OutputFilename, "output", "o", "", "output file: .md, .html, .pdf, or .json (required)")
	flags.StringVarP(&opts.Title, "title", "t", "", "report title (defaults to set name)")
	flags.StringVar(&opts.Subtitle, "subtitle", "", "report subtitle")
	flags.StringVar(&opts.Organization, "organization", "", "organization name")
	flags.StringVar(&opts.Author, "author", "", "report author")
	flags.StringVar(&opts.Classification, "classification", "", "classification banner, e.g. Confidential")
	flags.StringVar(&opts.Summary, "summary", "", "executive summary text")
	flags.StringVar(&opts.Columns, "columns", "default", "findings columns: default or residual")
	if err := c.MarkFlagRequired("input"); err != nil {
		panic(err) // programming error: flag name mismatch
	}
	if err := c.MarkFlagRequired("output"); err != nil {
		panic(err) // programming error: flag name mismatch
	}
	return c
}

// Run reads the input, applies flag overrides, and writes the report.
func (opts *CmdReportOptions) Run() error {
	r, err := ReadReportOrSetFile(opts.InputFilename)
	if err != nil {
		return err
	}

	if opts.Title != "" {
		r.Title = opts.Title
	}
	if opts.Subtitle != "" {
		r.Subtitle = opts.Subtitle
	}
	if opts.Organization != "" {
		r.Organization = opts.Organization
	}
	if opts.Author != "" {
		r.Author = opts.Author
	}
	if opts.Classification != "" {
		r.Classification = opts.Classification
	}
	if opts.Summary != "" {
		r.Summary = opts.Summary
	}
	if r.Title == "" {
		if r.Set != nil && strings.TrimSpace(r.Set.Name) != "" {
			r.Title = r.Set.Name
		} else {
			r.Title = "Vulnerability Report"
		}
	}
	if r.GeneratedAt == nil {
		now := time.Now().UTC()
		r.GeneratedAt = &now
	}

	switch strings.ToLower(strings.TrimSpace(opts.Columns)) {
	case "", "default":
		// keep any column set loaded with the report
	case "residual":
		cols := ResidualColumnDefinitionSet()
		r.ColumnSet = &cols
	default:
		return fmt.Errorf("columns not supported (%s): use default or residual", opts.Columns)
	}

	return r.WriteFileFormat(opts.OutputFilename, 0600)
}

// ReadReportOrSetFile reads a JSON file containing either a vulnreport
// Report or a govex VulnerabilitiesSet, returning a Report in both cases.
func ReadReportOrSetFile(filename string) (*Report, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	r := Report{}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filename, err)
	}
	if r.Title != "" || r.Set != nil {
		return &r, nil
	}
	set := govex.VulnerabilitiesSet{}
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filename, err)
	}
	if strings.TrimSpace(set.Name) == "" && len(set.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("file is neither a report nor a vulnerabilities set (%s)", filename)
	}
	return &Report{Title: set.Name, Set: &set}, nil
}

// WriteFileFormat writes the report in the format inferred from the
// filename extension: .md, .html/.htm, .pdf, or .json.
func (r *Report) WriteFileFormat(filename string, perm os.FileMode) error {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".md", ".markdown":
		return r.WriteMarkdownFile(filename, perm)
	case ".html", ".htm":
		return r.WriteHTMLFile(filename, perm)
	case ".pdf":
		return r.WritePDFFile(filename, perm)
	case ".json":
		return r.WriteJSONFile(filename, perm)
	default:
		return fmt.Errorf("output format not supported (%s): use .md, .html, .pdf, or .json", filepath.Ext(filename))
	}
}
