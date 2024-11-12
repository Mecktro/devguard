// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package commands

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"

	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/spf13/cobra"
)

func tokenToKey(token string) (string, error) {
	// transform the hex private key to an ecdsa private key
	privKey, _, err := pat.HexTokenToECDSA(token)
	if err != nil {
		slog.Error("could not convert hex token to ecdsa private key", "err", err)
		os.Exit(1)
	}

	// encode the private key to PEM
	privKeyBytes, err := x509.MarshalECPrivateKey(&privKey)
	if err != nil {
		slog.Error("could not marshal private key", "err", err)
		return "", err
	}
	// create a new temporary file to store the private key - the file needs to have minimum permissions
	tempDir := os.TempDir()

	file, err := os.OpenFile(path.Join(tempDir, "ecdsa.pem"), os.O_CREATE|os.O_WRONLY, 0600)

	if err != nil {
		slog.Error("could not create file", "err", err)
		return "", err
	}
	// remove the file after the function ends
	defer os.Remove(path.Join(tempDir, "ecdsa.pem"))

	// encode the private key to PEM
	err = pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		slog.Error("could not encode private key to PEM", "err", err)
		return "", err
	}

	var out bytes.Buffer
	var errOut bytes.Buffer

	// import the cosign key
	importCmd := exec.Command("cosign", "import-key-pair", "--output-key-prefix", "cosign", "--key", "ecdsa.pem")
	importCmd.Dir = tempDir
	importCmd.Stdout = &out
	importCmd.Stderr = &errOut
	importCmd.Env = []string{"COSIGN_PASSWORD="}

	err = importCmd.Run()
	if err != nil {
		slog.Error("could not import key", "err", err, "out", out.String(), "errOut", errOut.String())
		return "", err
	}

	return path.Join(tempDir, "cosign.key"), nil
}

func signCmd(cmd *cobra.Command, args []string) error {
	token, err := cmd.Flags().GetString("token")
	if err != nil {
		slog.Error("could not get token", "err", err)
		return err
	}

	// transform the hex private key to an ecdsa private key
	keyPath, err := tokenToKey(token)

	var out bytes.Buffer
	var errOut bytes.Buffer

	defer os.Remove(keyPath)

	// check if the argument is a file, which does exist
	fileOrImageName := args[0]
	if _, err := os.Stat(fileOrImageName); os.IsNotExist(err) {
		// the file does not exist - lets expect it to be an image
		// use the cosign cli to sign the file
		signBlobCmd := exec.Command("cosign", "sign-blob", "--tlog-upload=false", "--key", keyPath, args[0]) // nolint:gosec

		signBlobCmd.Stdout = &out
		signBlobCmd.Stderr = &errOut
		signBlobCmd.Env = []string{"COSIGN_PASSWORD="}

		err = signBlobCmd.Run()
		if err != nil {
			slog.Error("could not sign blob", "err", err, "out", out.String(), "errOut", errOut.String())
			return err
		}

		// print the signature
		fmt.Println(out.String())
		return nil
	}
	// it is an image
	signImageCmd := exec.Command("cosign", "sign", "--tlog-upload=false", "--key", keyPath, args[0]) // nolint:gosec
	signImageCmd.Stdout = &out
	signImageCmd.Stderr = &errOut
	signImageCmd.Env = []string{"COSIGN_PASSWORD="}

	err = signImageCmd.Run()
	if err != nil {
		slog.Error("could not sign image", "err", err, "out", out.String(), "errOut", errOut.String())
		return err
	}

	slog.Info("signature", "signature", out.String())

	return nil
}

func NewSignCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign <file | image>",
		Short: "Sign a file or image",
		Long:  `Sign a file or image`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			err := signCmd(cmd, args)
			if err != nil {
				slog.Error("signing failed", "err", err)
				os.Exit(1)
			}
		},
	}

	cmd.PersistentFlags().String("token", "", "The personal access token to authenticate the request")

	cmd.MarkPersistentFlagRequired("token") // nolint:errcheck

	return cmd
}
