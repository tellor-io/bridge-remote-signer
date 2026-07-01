package main

import (
	"fmt"
	"os"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/spf13/cobra"

	"github.com/tellor-io/bridge-remote-signer/signer"
)

const tellorBech32Prefix = "tellor"

// newRootCmd builds the bridge-signer cobra tree: a keys subtree (cosmos-sdk's, minus export/import/migrate, plus our raw hex export) and start (daemon).
func newRootCmd() *cobra.Command {
	configureBech32Once()

	cdc := signer.MakeKeyringCodec()

	initClientCtx := client.Context{}.
		WithCodec(cdc).
		WithInterfaceRegistry(cdc.InterfaceRegistry()).
		WithInput(os.Stdin)

	rootCmd := &cobra.Command{
		Use:           "bridge-signer",
		Short:         "Tellor bridge attestation signing daemon and key management",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// Block non-file keyring backends.
			if f := cmd.Flags().Lookup(flags.FlagKeyringBackend); f != nil {
				if cmd.Flags().Changed(flags.FlagKeyringBackend) && f.Value.String() != keyring.BackendFile {
					return fmt.Errorf("only --keyring-backend=file is supported, got %q", f.Value.String())
				}
				_ = f.Value.Set(keyring.BackendFile)
			}

			// Require --keyring-dir for keyring touching commands.
			if needsKeyringDir(cmd) {
				keyringDir, err := cmd.Flags().GetString(flags.FlagKeyringDir)
				if err != nil {
					return fmt.Errorf("get --keyring-dir: %w", err)
				}
				if keyringDir == "" {
					return fmt.Errorf("--keyring-dir is required for %q", cmd.CommandPath())
				}
			}

			cmd.SetOut(cmd.OutOrStdout())
			cmd.SetErr(cmd.ErrOrStderr())

			ctx := initClientCtx.WithCmdContext(cmd.Context())
			ctx, err := client.ReadPersistentCommandFlags(ctx, cmd.Flags())
			if err != nil {
				return err
			}
			return client.SetCmdClientContextHandler(ctx, cmd)
		},
	}

	keysCmd := bridgeSignerKeysCmd()
	keysCmd.AddCommand(exportCmd())

	rootCmd.AddCommand(
		keysCmd,
		startCmd(),
		initStateCmd(),
	)

	return rootCmd
}

// bridgeSignerKeysCmd returns the cosmos-sdk keys subtree minus export/import/migrate.
func bridgeSignerKeysCmd() *cobra.Command {
	cmd := keys.Commands()

	banned := map[string]bool{"export": true, "import": true, "migrate": true}
	var toRemove []*cobra.Command
	for _, sub := range cmd.Commands() {
		if banned[sub.Name()] {
			toRemove = append(toRemove, sub)
		}
	}
	cmd.RemoveCommand(toRemove...)

	if f := cmd.LocalFlags().Lookup(flags.FlagKeyringBackend); f != nil {
		f.Hidden = true
	}
	if f := cmd.LocalFlags().Lookup(flags.FlagKeyringDir); f != nil {
		f.Usage = "keyring directory"
	}

	cmd.Short = "Manage keys in the bridge-signer keyring"
	cmd.Long = `Manage keys in the bridge-signer keyring.

Keys are stored encrypted on disk in the file backend at --keyring-dir,
with the encryption passphrase prompted at each operation. Other
cosmos-sdk backends (os, kwallet, pass, test, memory) are not supported.

Subcommands add and import-hex to create or restore a key, 
show and list to inspect, rename to move within a keyring,
delete to remove, export to dump the raw hex private key to a
0600 file (refuses to print to a terminal).`
	return cmd
}

// needsKeyringDir reports whether cmd touches the cosmos-sdk keyring. The daemon (start)
// and the state-file bootstrap (init-state) do not.
func needsKeyringDir(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Name() == "start" || c.Name() == "init-state" {
			return false
		}
	}
	return true
}

// configureBech32Once sets the Tellor bech32 prefix on sdk.Config so addresses render as tellor1... rather than cosmos1...; idempotent.
func configureBech32Once() {

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(tellorBech32Prefix, tellorBech32Prefix+"pub")
	cfg.SetBech32PrefixForValidator(tellorBech32Prefix+"valoper", tellorBech32Prefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(tellorBech32Prefix+"valcons", tellorBech32Prefix+"valconspub")
	cfg.Seal()

}
