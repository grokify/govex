package govex

import (
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/grokify/sogo/flag/cobrautil"
	"github.com/jessevdk/go-flags"
	"github.com/spf13/cobra"
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
		return opts.Exec()
	}
}

func (opts *CmdSiteWriteHomeOptions) ParseCLI() error {
	_, err := flags.Parse(&opts)
	return err
}

func (opts *CmdSiteWriteHomeOptions) Exec() error {
	sw := DefaultSiteWriterHome(opts.ReportRepoURL, opts.RootIndexShieldsMarkdown)
	return sw.WriteFileHome()
}

func (opts *CmdSiteWriteHomeOptions) RunCobra(cmd *cobra.Command, args []string) {
	if err := opts.RunCobraError(cmd, args); err != nil {
		slog.Error("error running cobra command", "errorMessage", err.Error())
		os.Exit(1)
	}
}

func (opts *CmdSiteWriteHomeOptions) RunCobraError(cmd *cobra.Command, args []string) error {
	if cmd == nil {
		return errors.New("cobra.Command cannot be nil")
	}
	if val, err := cmd.Flags().GetString("reportRepoURL"); err != nil {
		return err
	} else {
		opts.ReportRepoURL = val
	}
	if val, err := cmd.Flags().GetString("shieldsMarkdown"); err != nil {
		return err
	} else {
		opts.RootIndexShieldsMarkdown = val
	}

	return opts.Exec()
}

func CmdSiteWriteHomeCobra(cmdName string) (*cobra.Command, error) {
	cmdName = strings.TrimSpace(cmdName)
	if cmdName == "" {
		cmdName = "writesitehomepage"
	}
	opts := &CmdSiteWriteHomeOptions{}
	var homepageCmd = &cobra.Command{
		Use:   cmdName,
		Short: "Write status site homepage",
		Long:  `Updates the site homepage by walking the folder structure for report updates.`,
		Run:   opts.RunCobra,
	}

	if err := cobrautil.AddFlags(homepageCmd, opts); err != nil {
		return nil, err
	} else {
		return homepageCmd, nil
	}
}
