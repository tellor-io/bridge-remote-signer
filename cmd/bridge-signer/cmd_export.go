package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/tellor-io/bridge-remote-signer/signer"
)

// exportCmd replaces `keys export --unarmored-hex --unsafe` with a TTY refusing, no overwrite, 0600 file variant.
func exportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export <key-name>",
		Short: "Export the raw hex-encoded private key from the keyring",
		Long: `Export the raw hex-encoded secp256k1 private key from the keyring.

Output is written to --output (a file with mode 0600, refusing to
overwrite) or to stdout. Stdout is rejected when it is a terminal, to
prevent the key from appearing in scrollback or screen-sharing.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			keyName := args[0]
			outputPath, err := cmd.Flags().GetString("output")
			if err != nil {
				return fmt.Errorf("get output path: %w", err)
			}
			return runExport(clientCtx, keyName, outputPath)
		},
	}
	cmd.Flags().String("output", "", "write hex private key to this file with mode 0600 (refuses to overwrite)")
	return cmd
}

func runExport(clientCtx client.Context, keyName, outputPath string) error {
	record, err := clientCtx.Keyring.Key(keyName)
	if err != nil {
		return fmt.Errorf("get key %q from keyring at %q: %w", keyName, clientCtx.KeyringDir, err)
	}

	keyBytes, err := signer.ExtractSecpPrivKeyBytes(clientCtx.Codec, record)
	if err != nil {
		return err
	}

	hexEncoded := hex.EncodeToString(keyBytes)

	if outputPath != "" {
		return writeKeyToFile(outputPath, hexEncoded)
	}

	if term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New(
			"refusing to write private key to a terminal; " +
				"redirect stdout to a file/pipe or use --output to write to a file with mode 0600",
		)
	}

	fmt.Fprintln(os.Stderr, "WARNING: emitting raw private key hex to stdout. Anything that captures this stream gets the key.")
	if _, err := fmt.Fprintln(os.Stdout, hexEncoded); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

// writeKeyToFile writes hexEncoded to path atomically at mode 0600, refusing to overwrite.
func writeKeyToFile(path, hexEncoded string) error {
	if err := signer.WriteNewFileAtomic(path, []byte(hexEncoded+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Private key written to %s (mode 0600)\n", path)
	return nil
}
