package govex

import (
	"github.com/jessevdk/go-flags"
)

type CLIMergeJSONs2XLSXOptions struct {
	InputFilename           []string `short:"i" long:"inputfile" description:"Filenames to merge" required:"true"`
	OutputFileJSON          string   `short:"o" long:"outputFile" description:"Outputfile" required:"false"`
	OutputFileXLSX          string   `short:"x" long:"xlsxoutputFile" description:"Outputfile in XLSX format" required:"true"`
	DoNowSeverityCutOffIncl string   `short:"s" long:"severityfiltercutoff" description:"Outputfile" required:"false"`
}

func CLIMergeJSONs2XLSXExec() error {
	opts := CLIMergeJSONs2XLSXOptions{}
	_, err := flags.Parse(&opts)
	if err != nil {
		return err
	}

	vs, err := ReadFilesVulnerabilitiesSet(opts.InputFilename)
	if err != nil {
		return err
	}
	if opts.OutputFileJSON != "" {
		err := vs.WriteFileJSON(opts.OutputFileJSON, "", "  ", 0600)
		if err != nil {
			return err
		}
	}
	if opts.OutputFileXLSX != "" {
		err := vs.Vulnerabilities.WriteFileXLSXSplitSeverity(
			opts.OutputFileXLSX,
			TableColumnDefinitionSetSASTSCA(),
			opts.DoNowSeverityCutOffIncl,
			P1DoNow, P2DoNext, nil)
		if err != nil {
			return err
		}
	}
	return nil
}
