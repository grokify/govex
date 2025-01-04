package govex

import (
	"github.com/jessevdk/go-flags"
)

type CLISiteWriteHomeOptions struct {
	ReportRepoURL string `short:"r" long:"reportRepoURL" description:"Outputfile" required:"true"`
}

func CLISiteWriteHomeExec() error {
	opts := CLISiteWriteHomeOptions{}
	if _, err := flags.Parse(&opts); err != nil {
		return err
	} else {
		sw := DefaultSiteWriterHome(opts.ReportRepoURL)
		return sw.WriteFileHome()
	}
}
