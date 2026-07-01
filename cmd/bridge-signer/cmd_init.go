package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tellor-io/bridge-remote-signer/config"
	"github.com/tellor-io/bridge-remote-signer/consensus"
)

// initStateCmd bootstraps a brand-new signer by creating a fresh consensus state file.
// It is a one-shot command, deliberately separate from `start`: `start` never creates the
// state file, so a run command that restarts repeatedly can neither crash-loop on an
// existing file nor silently reset the double-sign high-water-mark.
func initStateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init-state",
		Short: "Create a fresh consensus state file for a brand-new signer (one-shot)",
		Long: `Create a fresh zero last-sign state file (priv_validator_state.json) for a
brand-new signer. Refuses if one already exists, so it can never overwrite a real
last-sign state. Run this once at bootstrap; 'start' never creates the state file.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if err := consensus.InitStateFile(cfg.Consensus.StateFile); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "created fresh consensus state file: %s\n", cfg.Consensus.StateFile)
			return nil
		},
	}
	cmd.Flags().String("config", "config.yaml", "path to config file")
	return cmd
}
