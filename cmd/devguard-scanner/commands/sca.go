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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/dependency_vuln"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func maybeGetFileName(path string) (string, bool) {
	l, err := os.Stat(path)
	if err != nil {
		return "", false
	}

	if l.IsDir() {
		return path, true
	}
	return filepath.Base(path), false
}

func generateSBOM(path string) (*os.File, error) {
	filename := uuid.New().String() + ".json"
	maybeFilename, isDir := maybeGetFileName(path)
	var trivyCmd *exec.Cmd
	if isDir {
		slog.Info("scanning directory", "dir", path)
		trivyCmd = exec.Command("trivy", "fs", ".", "--format", "cyclonedx", "--output", filename)
	} else {
		slog.Info("scanning single file", "file", maybeFilename)
		trivyCmd = exec.Command("trivy", "image", "--input", filepath.Base(path), "--format", "cyclonedx", "--output", filename)
	}

	stderr := &bytes.Buffer{}
	trivyCmd.Stderr = stderr
	trivyCmd.Dir = getDirFromPath(path)
	err := trivyCmd.Run()
	if err != nil {
		return nil, errors.Wrap(err, stderr.String())
	}

	return os.Open(filepath.Join(getDirFromPath(path), filename))
}

func sanitizeApiUrl(apiUrl string) string {
	apiUrl = strings.TrimSuffix(apiUrl, "/")
	if !strings.HasPrefix(apiUrl, "http://") && !strings.HasPrefix(apiUrl, "https://") {
		apiUrl = "https://" + apiUrl
	}
	return apiUrl
}

func parseConfig(cmd *cobra.Command) (string, string, string, string, string) {
	token, err := cmd.PersistentFlags().GetString("token")
	if err != nil {
		slog.Error("could not get token", "err", err)
		return "", "", "", "", ""
	}
	assetName, err := cmd.PersistentFlags().GetString("assetName")
	if err != nil {
		slog.Error("could not get asset id", "err", err)
		return "", "", "", "", ""
	}
	apiUrl, err := cmd.PersistentFlags().GetString("apiUrl")
	if err != nil {
		slog.Error("could not get api url", "err", err)
		return "", "", "", "", ""
	}
	apiUrl = sanitizeApiUrl(apiUrl)

	failOnRisk, err := cmd.Flags().GetString("fail-on-risk")
	if err != nil {
		slog.Error("could not get fail-on-risk", "err", err)
		return "", "", "", "", ""
	}

	webUI, err := cmd.Flags().GetString("webUI")
	if err != nil {
		slog.Error("could not get webUI", "err", err)
		return "", "", "", "", ""
	}

	return token, assetName, apiUrl, failOnRisk, webUI
}

func dependencyVulnToTableRow(pURL packageurl.PackageURL, v dependency_vuln.DependencyVulnDTO, assetVersion string, clickableLink string) table.Row {
	basePkg := fmt.Sprintf("pkg:%s/%s", pURL.Type, pURL.Name)
	if pURL.Namespace != "" {
		basePkg = fmt.Sprintf("pkg:%s/%s/%s", pURL.Type, pURL.Namespace, pURL.Name)
	}

	finalURL := fmt.Sprintf("%s/refs/%s/flaws/%s", clickableLink, assetVersion, v.ID)
	return table.Row{basePkg, utils.SafeDereference(v.CVEID), utils.OrDefault(v.RawRiskAssessment, 0), strings.TrimPrefix(pURL.Version, "v"), utils.SafeDereference(v.ComponentFixedVersion), v.State, finalURL}
}

func printScaResults(scanResponse scan.ScanResponse, failOnRisk, assetName, webUI string, doRiskManagement bool, assetVersion string) {
	slog.Info("Scan completed successfully", "dependencyVulnAmount", len(scanResponse.DependencyVulns))
	if len(scanResponse.DependencyVulns) == 0 {
		return
	}

	slices.SortFunc(scanResponse.DependencyVulns, func(a, b dependency_vuln.DependencyVulnDTO) int {
		return int(utils.OrDefault(a.RawRiskAssessment, 0)*100) - int(utils.OrDefault(b.RawRiskAssessment, 0)*100)
	})

	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"Library", "Vulnerability", "Risk", "Installed", "Fixed", "Status", "URL"})
	tw.AppendRows(utils.Map(scanResponse.DependencyVulns, func(v dependency_vuln.DependencyVulnDTO) table.Row {
		clickableLink := fmt.Sprintf("%s/%s", webUI, assetName)
		return dependencyVulnToTableRow(packageurl.MustParse(*v.ComponentPurl), v, assetVersion, clickableLink)
	}))

	fmt.Println(tw.Render())
}
