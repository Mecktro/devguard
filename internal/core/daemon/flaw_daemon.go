package daemon

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

func getFixedVersion(purlComparer *scan.PurlComparer, dependencyVuln models.DependencyVulnerability) (*string, error) {
	// we only need to update the fixed version
	// update the fixed version
	affected, err := purlComparer.GetAffectedComponents(*dependencyVuln.ComponentPurl, "")
	if err != nil {
		return nil, err
	}
	// check if there is a fix for the dependencyVuln
	for _, c := range affected {
		// check if this affected component comes from the same cve
		if !utils.Contains(utils.Map(c.CVE, func(c models.CVE) string {
			return c.CVE
		}), *dependencyVuln.CVEID) {
			continue
		}

		if c.SemverFixed != nil {
			slog.Info("found fixed version", "purl", *dependencyVuln.ComponentPurl, "fixedVersion", *c.SemverFixed, "dependencyVulnId", dependencyVuln.ID)
			return c.SemverFixed, nil
		} else if c.VersionFixed != nil && *c.VersionFixed != "" {
			slog.Info("found fixed version", "purl", *dependencyVuln.ComponentPurl, "fixedVersion", *c.VersionFixed, "dependencyVulnId", dependencyVuln.ID)
			return c.VersionFixed, nil
		}
	}

	return nil, nil
}

func UpdateComponentProperties(db database.DB) error {
	// we need to update component depth and fixedVersion for each dependencyVuln.
	// to make this as efficient as possible, we start by getting all the assets
	// and then we get all the components for each asset.

	assetRepository := repositories.NewAssetRepository(db)
	purlComparer := scan.NewPurlComparer(db)
	componentRepository := repositories.NewComponentRepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnerability(db)

	allAssets, err := assetRepository.GetAllAssetsFromDB()
	if err != nil {
		return err
	}

	wg := utils.ErrGroup[any](5)

	for _, a := range allAssets {
		wg.Go(func() (any, error) {
			slog.Info("updating asset", "asset", a.ID)
			now := time.Now()
			defer func() {
				slog.Info("updated asset", "asset", a.ID, "duration", time.Since(now))
			}()
			// get all dependencyVulns of that asset
			dependencyVulns, err := dependencyVulnRepository.GetByAssetId(nil, a.ID)
			if err != nil {
				slog.Warn("could not get dependencyVulns", "asset", a.ID, "err", err)
				return nil, err
			}

			// group by scanner id
			groups := make(map[string][]models.DependencyVulnerability)
			for _, f := range dependencyVulns {
				if _, ok := groups[f.ScannerID]; !ok {
					groups[f.ScannerID] = []models.DependencyVulnerability{}
				}

				groups[f.ScannerID] = append(groups[f.ScannerID], f)
			}

			// group the dependencyVulns by scanner id
			// build up the dependency tree for the asset
			for scannerID, dependencyVulns := range groups {
				components, err := componentRepository.LoadComponents(nil, a, scannerID, "")
				if err != nil {
					slog.Warn("could not load components", "asset", a.ID, "scanner", scannerID, "err", err)
					continue
				}

				depthMap := asset.GetComponentDepth(components)

				for _, dependencyVuln := range dependencyVulns {
					depth := depthMap[*dependencyVuln.ComponentPurl]
					if dependencyVuln.ComponentFixedVersion != nil && dependencyVuln.ComponentDepth != nil && depth == *dependencyVuln.ComponentDepth {
						continue // nothing todo here - the component has a depth which is the same and it already has a fix version
					}

					doUpdate := false

					if dependencyVuln.ComponentFixedVersion == nil {
						fixedVersion, err := getFixedVersion(purlComparer, dependencyVuln)
						slog.Info("got fixed version", "fixedVersion", fixedVersion)
						if err != nil {
							slog.Warn("could not get fixed version", "err", err)
						}
						if fixedVersion != nil {
							dependencyVuln.ComponentFixedVersion = fixedVersion
							doUpdate = true
						}
					}

					if dependencyVuln.ComponentDepth == nil || depth != *dependencyVuln.ComponentDepth {
						dependencyVuln.ComponentDepth = utils.Ptr(depth)
						doUpdate = true
					}

					if !doUpdate {
						continue
					}

					// save the dependencyVuln
					if err := dependencyVulnRepository.Save(nil, &dependencyVuln); err != nil {
						slog.Warn("could not save dependencyVuln", "dependencyVuln", dependencyVuln.ID, "err", err)
					}
				}

			}
			return nil, nil
		})
	}

	_, err = wg.WaitAndCollect()
	if err != nil {
		slog.Error("could not update component properties", "err", err)
		return err
	}

	return nil
}
