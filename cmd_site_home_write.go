package govex

import (
	"github.com/jessevdk/go-flags"
)

type CmdSiteWriteHomeOptions struct {
	ReportRepoURL            string `short:"r" long:"reportRepoURL" description:"Outputfile" required:"true"`
	RootIndexShieldsMarkdown string `short:"s" long:"shieldsMarkdown" description:"Shields Markdown" required:"false"`
}

func CmdSiteWriteHomeExec() error {
	opts := CmdSiteWriteHomeOptions{}
	if _, err := flags.Parse(&opts); err != nil {
		return err
	} else {
		sw := DefaultSiteWriterHome(opts.ReportRepoURL, opts.RootIndexShieldsMarkdown)
		return sw.WriteFileHome()
	}
}
