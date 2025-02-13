package daemon

import (
	"github.com/l3montree-dev/devguard/internal/core/DependencyVuln"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func RecalculateRisk(db database.DB) error {
	flawService := DependencyVuln.NewService(
		repositories.NewDependencyVulnerability(db),
		repositories.NewFlawEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
	)

	return flawService.RecalculateAllRawRiskAssessments()
}
