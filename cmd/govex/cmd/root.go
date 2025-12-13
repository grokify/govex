package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/grokify/govex/reports/sitewriter"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "govex",
	Short: "Govex CLI",
	Long:  `Govex CLI including merge and sitewriter commands.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	if mergeCmd, err := sitewriter.CmdMergeJSONsCobra(""); err != nil {
		slog.Error("Error marking flag required", "errorMessage", err.Error())
		os.Exit(1)
	} else {
		rootCmd.AddCommand(mergeCmd)
	}
	if homepageCmd, err := sitewriter.CmdSiteWriteHomeCobra(""); err != nil {
		slog.Error("Error marking flag required", "errorMessage", err.Error())
		os.Exit(2)
	} else {
		rootCmd.AddCommand(homepageCmd)
	}
}
