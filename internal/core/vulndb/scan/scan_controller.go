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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package scan

import (
	"fmt"
	"log/slog"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type cveRepository interface {
	FindAll(cveIDs []string) ([]models.CVE, error)
}

type componentRepository interface {
	SaveBatch(tx core.DB, components []models.Component) error
	LoadComponents(tx core.DB, asset models.AssetVersion, scanner, version string) ([]models.ComponentDependency, error)
}

type assetVersionService interface {
	HandleScanResult(asset models.AssetNew, assetVersion models.AssetVersion, vulns []models.VulnInPackage, scanner string, version string, scannerID string, userID string, doRiskManagement bool) (amountOpened int, amountClose int, newState []models.Flaw, err error)
	UpdateSBOM(asset models.AssetVersion, scanner string, version string, sbom normalize.SBOM) error
}

type assetRepository interface {
	GetAllAssetsFromDB() ([]models.AssetNew, error)
	Save(tx core.DB, asset *models.AssetNew) error
}

type assetVersionRepository interface {
	FindOrCreate(assetVersionName string, assetID uuid.UUID, tag string) (models.AssetVersion, error)
}

type statisticsService interface {
	UpdateAssetRiskAggregation(assetID uuid.UUID, begin time.Time, end time.Time, updateProject bool) error
}

type httpController struct {
	db                     core.DB
	sbomScanner            *sbomScanner
	cveRepository          cveRepository
	componentRepository    componentRepository
	assetRepository        assetRepository
	assetVersionRepository assetVersionRepository
	assetVersionService    assetVersionService
	statisticsService      statisticsService
}

func NewHttpController(db core.DB, cveRepository cveRepository, componentRepository componentRepository, assetRepository assetRepository, assetVersionRepository assetVersionRepository, assetVersionService assetVersionService, statisticsService statisticsService) *httpController {
	cpeComparer := NewCPEComparer(db)
	purlComparer := NewPurlComparer(db)

	scanner := NewSBOMScanner(cpeComparer, purlComparer, cveRepository)
	return &httpController{
		db:                     db,
		sbomScanner:            scanner,
		cveRepository:          cveRepository,
		componentRepository:    componentRepository,
		assetVersionService:    assetVersionService,
		assetRepository:        assetRepository,
		assetVersionRepository: assetVersionRepository,
		statisticsService:      statisticsService,
	}
}

type ScanResponse struct {
	AmountOpened int            `json:"amountOpened"`
	AmountClosed int            `json:"amountClosed"`
	Flaws        []flaw.FlawDTO `json:"flaws"`
}

func (s *httpController) Scan(c core.Context) error {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(c.Request().Body, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return err
	}
	normalizedBom := normalize.FromCdxBom(bom, true)

	asset := core.GetAsset(c)

	userID := core.GetSession(c).GetUserID()

	// get the X-Asset-Version header
	version := c.Request().Header.Get("X-Asset-Version")
	if version == "" {
		version = models.NoVersion
	}

	tag := c.Request().Header.Get("X-Tag")

	assetVersionName := c.Request().Header.Get("X-Asset-Version-New")
	assetVersion, err := s.assetVersionRepository.FindOrCreate(assetVersionName, asset.ID, tag)
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		return c.JSON(500, map[string]string{"error": "could not find or create asset version"})
	}

	scanner := c.Request().Header.Get("X-Scanner")
	if scanner == "" {
		slog.Error("no X-Scanner header found")
		return c.JSON(400, map[string]string{
			"error": "no X-Scanner header found",
		})
	}

	if version != models.NoVersion {
		var err error
		version, err = normalize.SemverFix(version)
		// check if valid semver
		if err != nil {
			slog.Error("invalid semver version", "version", version)
			return c.JSON(400, map[string]string{"error": "invalid semver version"})
		}
	}
	//check if risk management is enabled
	riskManagementEnabled := c.Request().Header.Get("X-Risk-Management")
	doRiskManagement := riskManagementEnabled != "false"

	if doRiskManagement {
		// update the sbom in the database in parallel
		if err := s.assetVersionService.UpdateSBOM(assetVersion, scanner, version, normalizedBom); err != nil {
			slog.Error("could not update sbom", "err", err)
			return c.JSON(500, map[string]string{"error": "could not update sbom"})
		}

	}

	fmt.Println("normalizedBom", normalizedBom)

	// scan the bom we just retrieved.
	vulns, err := s.sbomScanner.Scan(normalizedBom)

	if err != nil {
		slog.Error("could not scan file", "err", err)
		return c.JSON(500, map[string]string{"error": "could not scan file"})
	}

	scannerID := c.Request().Header.Get("X-Scanner")
	if scannerID == "" {
		return c.JSON(400, map[string]string{"error": "no scanner id provided"})
	}

	// handle the scan result
	amountOpened, amountClose, newState, err := s.assetVersionService.HandleScanResult(asset, assetVersion, vulns, scannerID, version, scannerID, userID, doRiskManagement)
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		return c.JSON(500, map[string]string{"error": "could not handle scan result"})
	}

	if doRiskManagement {
		slog.Info("recalculating risk history for asset", "asset", assetVersion.ID)
		if err := s.statisticsService.UpdateAssetRiskAggregation(assetVersion.ID, utils.OrDefault(assetVersion.LastHistoryUpdate, assetVersion.CreatedAt), time.Now(), true); err != nil {
			slog.Error("could not recalculate risk history", "err", err)
			return c.JSON(500, map[string]string{"error": "could not recalculate risk history"})
		}
	}

	return c.JSON(200, ScanResponse{
		AmountOpened: amountOpened,
		AmountClosed: amountClose,
		Flaws:        utils.Map(newState, flaw.FlawToDto)})
}
