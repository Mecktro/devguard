package vulnreport

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/application"
	"github.com/l3montree-dev/flawfix/internal/core/env"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
)

func RegisterHttpHandler(database core.DB, server core.Server) {

	applicationRepository := application.NewGormRepository(database)
	flawRepository := flaw.NewGormRepository(database)
	flawEventRepository := flawevent.NewGormRepository(database)
	envRepository := env.NewGormRepository(database)

	controller := NewHttpController(
		applicationRepository,
		flawRepository,
		flawEventRepository,
		envRepository,
	)

	vulnreportRouter := server.Group("/vulnreports")
	vulnreportRouter.POST("/:envID/", controller.ImportVulnReport)
}
