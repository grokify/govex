package govex

import (
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/grokify/mogo/pointer"
	"github.com/grokify/sogo/flag/cobrautil"
	"github.com/jessevdk/go-flags"
	"github.com/spf13/cobra"
)

type CmdMergeJSONsOptions struct {
	InputFilename     []string `short:"i" long:"inputFiles" description:"Input filenames to merge" required:"true"`
	OutputFileJSON    string   `short:"o" long:"outputFile" description:"Outputfile in JSON format" required:"false"`
	OutputFileXLSX    string   `short:"x" long:"xlsxOutputFile" description:"Outputfile in XLSX format" required:"false"`
	OutputFileMKDN    string   `short:"m" long:"markdownOutputFile" description:"Outputfile in Markdown format" required:"true"`
	SeveritySplitXLSX string   `short:"s" long:"severityFilterCutoff" description:"Outputfile" required:"false"`
	ReportRepoURL     string   `short:"r" long:"reportRepoURL" description:"Outputfile" required:"false"`
	ProjectName       string   `short:"n" long:"projectName" description:"Project name to use" required:"false"`
	ProjectRepoPath   string   `short:"p" long:"repoPath" description:"Project repo path" required:"false"`
	ProjectRepoURL    string   `short:"u" long:"repoURL" description:"Project repo URL" required:"false"`
}

type CmdMergeJSONsResponse struct {
	RequestOptions       *CmdMergeJSONsOptions
	Sheet1Len            int
	Sheet2Len            int
	FilesWritten         []string
	SeverityCountsString string
	ReportRepoUpdated    bool
}

func CmdMergeJSONsExec() (*CmdMergeJSONsResponse, error) {
	opts := CmdMergeJSONsOptions{}

	_, err := flags.Parse(&opts)
	if err != nil {
		return nil, err
	}
	return opts.Exec()
}

func (opts *CmdMergeJSONsOptions) ParseCLI() error {
	_, err := flags.Parse(&opts)
	return err
}

func (opts *CmdMergeJSONsOptions) RunCobra(cmd *cobra.Command, args []string) {
	if err := opts.RunCobraError(cmd, args); err != nil {
		slog.Error("error running cobra command", "errorMessage", err.Error())
		os.Exit(1)
	}
}

func (opts *CmdMergeJSONsOptions) RunCobraError(cmd *cobra.Command, args []string) error {
	if cmd == nil {
		return errors.New("cobra.Command cannot be nil")
	}
	if vals, err := cmd.Flags().GetStringSlice("inputFiles"); err != nil {
		return err
	} else {
		opts.InputFilename = vals
	}
	if val, err := cmd.Flags().GetString("outputFile"); err != nil {
		return err
	} else {
		opts.OutputFileJSON = val
	}
	if val, err := cmd.Flags().GetString("xlsxOutputFile"); err != nil {
		return err
	} else {
		opts.OutputFileXLSX = val
	}
	if val, err := cmd.Flags().GetString("markdownOutputFile"); err != nil {
		return err
	} else {
		opts.OutputFileMKDN = val
	}
	if val, err := cmd.Flags().GetString("severityFilterCutoff"); err != nil {
		return err
	} else {
		opts.SeveritySplitXLSX = val
	}
	if val, err := cmd.Flags().GetString("reportRepoURL"); err != nil {
		return err
	} else {
		opts.ReportRepoURL = val
	}
	if val, err := cmd.Flags().GetString("projectName"); err != nil {
		return err
	} else {
		opts.ProjectName = val
	}
	if val, err := cmd.Flags().GetString("repoPath"); err != nil {
		return err
	} else {
		opts.ProjectRepoPath = val
	}
	if val, err := cmd.Flags().GetString("repoURL"); err != nil {
		return err
	} else {
		opts.ProjectRepoURL = val
	}

	_, err := opts.Exec()
	return err
}

func (opts *CmdMergeJSONsOptions) Exec() (*CmdMergeJSONsResponse, error) {
	resp := CmdMergeJSONsResponse{
		RequestOptions: opts,
		Sheet1Len:      -1,
		Sheet2Len:      -1}

	// TODO: len1/len2/split are only implemented with XLSX.

	vs, err := ReadFilesVulnerabilitiesSet(opts.InputFilename...)
	if err != nil {
		return nil, err
	}
	// Add Merged Info.
	if strings.TrimSpace(opts.ProjectRepoURL) != "" {
		vs.SetRepoURL(opts.ProjectRepoURL)
	}
	if strings.TrimSpace(opts.ProjectRepoPath) != "" {
		vs.RepoPath = opts.ProjectRepoPath
	}
	if strings.TrimSpace(opts.ProjectName) != "" {
		vs.Name = opts.ProjectName
	}

	if vlns, err := vs.Vulnerabilities.Dedupe(); err != nil {
		return nil, err
	} else {
		vs.Vulnerabilities = vlns
	}

	if opts.ProjectName != "" {
		vs.Name = opts.ProjectName
	}
	vs.DateTime = pointer.Pointer(time.Now())

	resp.SeverityCountsString = vs.Vulnerabilities.SeverityCountsString(" ")

	if opts.OutputFileJSON != "" {
		err := vs.WriteFileJSON(opts.OutputFileJSON, "", "  ", 0600)
		if err != nil {
			return nil, err
		} else {
			resp.FilesWritten = append(resp.FilesWritten, opts.OutputFileJSON)
		}
	}

	if opts.OutputFileMKDN != "" {
		err := vs.WriteReportMarkdownTablesToFile(opts.OutputFileMKDN, 0600,
			"", TableColumnDefinitionSetSASTSCA(), true, nil)
		if err != nil {
			return nil, err
		} else {
			resp.FilesWritten = append(resp.FilesWritten, opts.OutputFileMKDN)
		}
	}

	if opts.OutputFileXLSX != "" {
		len1, len2, err := vs.Vulnerabilities.WriteFileXLSXSplitSeverity(
			opts.OutputFileXLSX,
			TableColumnDefinitionSetSASTSCA(),
			opts.SeveritySplitXLSX,
			P1DoNow, P2DoNext, nil)
		if err != nil {
			return nil, err
		}
		resp.Sheet1Len = len1
		resp.Sheet2Len = len2
		resp.FilesWritten = append(resp.FilesWritten, opts.OutputFileMKDN)
	} else {
		resp.Sheet1Len = len(vs.Vulnerabilities)
	}

	if strings.TrimSpace(opts.ReportRepoURL) != "" {
		if err := WriteFilesSiteForRepo(opts.ReportRepoURL, vs); err != nil {
			return &resp, err
		} else {
			resp.ReportRepoUpdated = true
		}
	}

	return &resp, nil
}

func CmdMergeJSONsCobra(cmdName string) (*cobra.Command, error) {
	cmdName = strings.TrimSpace(cmdName)
	if cmdName == "" {
		cmdName = "merge"
	}
	opts := &CmdMergeJSONsOptions{}
	var mergeCmd = &cobra.Command{
		Use:   cmdName,
		Short: "Merge GoVex files",
		Long:  `Merge GoVex JSON data files.`,
		Run:   opts.RunCobra,
	}

	if err := cobrautil.AddFlags(mergeCmd, opts); err != nil {
		return nil, err
	} else {
		return mergeCmd, nil
	}
}
