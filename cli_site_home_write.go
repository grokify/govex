package govex

import (
	"github.com/jessevdk/go-flags"
)

type CLISiteWriteHomeOptions struct {
	ReportRepoURL            string `short:"r" long:"reportRepoURL" description:"Outputfile" required:"true"`
	RootIndexShieldsMarkdown string `short:"s" long:"shieldsMarkdown" description:"Shields Markdown" required:"false"`
}

func CLISiteWriteHomeExec() error {
	opts := CLISiteWriteHomeOptions{}
	if _, err := flags.Parse(&opts); err != nil {
		return err
	} else {
		sw := DefaultSiteWriterHome(opts.ReportRepoURL, opts.RootIndexShieldsMarkdown)
		return sw.WriteFileHome()
	}
}
