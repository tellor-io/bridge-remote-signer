package signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	cosmossecp "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cryptoriums/layer-packages/webunlock"
	"github.com/tellor-io/bridge-remote-signer/logging"
	"golang.org/x/term"
)

const secp256k1KeyLen = 32

// MakeKeyringCodec builds a codec that registers the standard cosmos-sdk
// crypto interfaces. The keyring needs this to unmarshal the Any wrapped
// private and public keys it stores.
func MakeKeyringCodec() codec.Codec {
	registry := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(registry)
	return codec.NewProtoCodec(registry)
}

func BuildPasswordReader(passwordFile, webPort, keyringDir, keyName string) (io.Reader, error) {
	if strings.EqualFold(os.Getenv("KEYRING_UNLOCK_MODE"), "web") {
		pass, err := webUnlock(webPort, keyringDir, keyName)
		if err != nil {
			return nil, err
		}
		return strings.NewReader(pass + "\n"), nil
	}

	if passwordFile != "" {
		return buildFilePasswordReader(passwordFile)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("stdin is not a terminal; set the password file option or KEYRING_UNLOCK_MODE=web")
	}
	return os.Stdin, nil
}

func webUnlock(port, keyringDir, keyName string) (string, error) {
	if port == "" {
		port = "8888"
	}
	cdc := MakeKeyringCodec()
	addr := ":" + port
	log, err := logging.New("error", "json")
	if err != nil {
		return "", fmt.Errorf("create webunlock logger: %w", err)
	}
	return webunlock.WaitForUnlock(
		context.Background(),
		addr,
		func(pass string) error {
			return validateKeyringPass(pass, keyringDir, keyName, cdc)
		},
		log,
	)
}

func validateKeyringPass(pass, keyringDir, keyName string, cdc codec.Codec) error {
	kr, err := keyring.New(sdk.KeyringServiceName(), keyring.BackendFile, keyringDir, strings.NewReader(pass+"\n"), cdc)
	if err != nil {
		return err
	}
	_, _, err = kr.Sign(keyName, []byte("unlock validation"), 1)
	return err
}

func buildFilePasswordReader(path string) (io.Reader, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat password file %q: %w", path, err)
	}

	// Only 0600 mode is allowed.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf(
			"password file %q has permissions %04o; expected 0600",
			path, perm,
		)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read password file %q: %w", path, err)
	}

	password := bytes.TrimRight(data, "\r\n")
	if len(password) == 0 {
		return nil, fmt.Errorf("password file %q is empty", path)
	}

	line := append(bytes.Clone(password), '\n')
	return &repeatingReader{line: line}, nil
}

type repeatingReader struct {
	line []byte
	off  int
}

func (r *repeatingReader) Read(p []byte) (int, error) {
	if r.off >= len(r.line) {
		r.off = 0
	}
	n := copy(p, r.line[r.off:])
	r.off += n
	return n, nil
}

func ExtractSecpPrivKeyBytes(cdc codec.Codec, record *keyring.Record) ([]byte, error) {
	if record == nil {
		return nil, errors.New("nil keyring record")
	}

	localItem := record.GetLocal()
	if localItem == nil {
		return nil, fmt.Errorf("key %q is not a local key (ledger and multisig keys not supported)", record.Name)
	}

	var privKey cryptotypes.PrivKey
	if err := cdc.UnpackAny(localItem.PrivKey, &privKey); err != nil {
		return nil, fmt.Errorf("unpack private key for %q: %w", record.Name, err)
	}

	secp, ok := privKey.(*cosmossecp.PrivKey)
	if !ok {
		return nil, fmt.Errorf("key %q is %T, want *secp256k1.PrivKey", record.Name, privKey)
	}
	if len(secp.Key) != secp256k1KeyLen {
		return nil, fmt.Errorf("key %q has length %d, want %d", record.Name, len(secp.Key), secp256k1KeyLen)
	}

	out := make([]byte, secp256k1KeyLen)
	copy(out, secp.Key)
	return out, nil
}
