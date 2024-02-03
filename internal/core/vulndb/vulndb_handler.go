package vulndb

import (
	"github.com/l3montree-dev/flawfix/internal/core"
)

type configService interface {
	GetJSONConfig(key string, v any) error
	SetJSONConfig(key string, v any) error
}

type leaderElector interface {
	IsLeader() bool
}

func StartMirror(database core.DB, leaderElector leaderElector, configService configService) {
	cveRepository := NewGormRepository(database)
	cweRepository := NewGormCWERepository(database)

	nvdService := NewNVDService(leaderElector, configService, cveRepository)
	epssService := newEPSSService(nvdService, cveRepository)
	mitreService := newMitreService(leaderElector, cweRepository)
	// start the mirror process.
	vulnDBService := newVulnDBService(leaderElector, mitreService, epssService, nvdService)

	vulnDBService.startMirrorDaemon()
}
