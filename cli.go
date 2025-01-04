package govex

import (
	"strings"
	"time"

	"github.com/grokify/mogo/pointer"
	"github.com/jessevdk/go-flags"
)

type CLIMergeJSONsOptions struct {
	InputFilename     []string `short:"i" long:"inputFiles" description:"Filenames to merge" required:"true"`
	OutputFileJSON    string   `short:"o" long:"outputFile" description:"Outputfile in JSON format" required:"false"`
	OutputFileXLSX    string   `short:"x" long:"xlsxoOutputFile" description:"Outputfile in XLSX format" required:"false"`
	OutputFileMKDN    string   `short:"m" long:"markdownOutputFile" description:"Outputfile in Markdown format" required:"true"`
	SeveritySplitXLSX string   `short:"s" long:"severityfiltercutoff" description:"Outputfile" required:"false"`
	ReportRepoURL     string   `short:"r" long:"reportRepoURL" description:"Outputfile" required:"false"`
	ProjectName       string   `short:"p" long:"projectName" description:"Project name to use" required:"false"`
	ProjectRepoPath   string   `long:"repoPath" description:"Project: Repo Path" required:"false"`
	ProjectRepoURL    string   `long:"repoURL" description:"Project repoURL" required:"false"`
}

type CLIMergeJSONsResponse struct {
	RequestOptions       *CLIMergeJSONsOptions
	Sheet1Len            int
	Sheet2Len            int
	FilesWritten         []string
	SeverityCountsString string
	ReportRepoUpdated    bool
}

func CLIMergeJSONsExec() (*CLIMergeJSONsResponse, error) {
	opts := CLIMergeJSONsOptions{}

	_, err := flags.Parse(&opts)
	if err != nil {
		return nil, err
	}
	resp := CLIMergeJSONsResponse{
		RequestOptions: &opts,
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
