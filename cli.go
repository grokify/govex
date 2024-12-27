package govex

import (
	"time"

	"github.com/grokify/mogo/pointer"
	"github.com/jessevdk/go-flags"
)

type CLIMergeJSONs2XLSXOptions struct {
	InputFilename     []string `short:"i" long:"inputFiles" description:"Filenames to merge" required:"true"`
	ProjectName       string   `short:"p" long:"projectName" description:"Project name to use" required:"false"`
	OutputFileJSON    string   `short:"o" long:"outputFile" description:"Outputfile in JSON format" required:"false"`
	OutputFileXLSX    string   `short:"x" long:"xlsxoOutputFile" description:"Outputfile in XLSX format" required:"false"`
	OutputFileMKDN    string   `short:"m" long:"markdownOutputFile" description:"Outputfile in Markdown format" required:"true"`
	SeveritySplitXLSX string   `short:"s" long:"severityfiltercutoff" description:"Outputfile" required:"false"`
}

type CLIMergeJSONs2XLSXResponse struct {
	RequestOptions       *CLIMergeJSONs2XLSXOptions
	Sheet1Len            int
	Sheet2Len            int
	FilesWritten         []string
	SeverityCountsString string
}

func CLIMergeJSONs2XLSXExec() (*CLIMergeJSONs2XLSXResponse, error) {
	opts := CLIMergeJSONs2XLSXOptions{}

	_, err := flags.Parse(&opts)
	if err != nil {
		return nil, err
	}
	resp := CLIMergeJSONs2XLSXResponse{
		RequestOptions: &opts,
		Sheet1Len:      -1,
		Sheet2Len:      -1}

	// TODO: len1/len2/split are only implemented with XLSX.

	vs, err := ReadFilesVulnerabilitiesSet(opts.InputFilename)
	if err != nil {
		return nil, err
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
		err := vs.WriteReportMarkdownTableToFile(opts.OutputFileMKDN, 0600,
			TableColumnDefinitionSetSASTSCA(), true, nil)
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

	return &resp, nil
}
