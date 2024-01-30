package pat

import (
	"github.com/l3montree-dev/flawfix/internal/core"
)

func RegisterHttpHandler(database core.DB, server core.Server) core.Server {
	if err := database.AutoMigrate(&Model{}); err != nil {
		panic(err)
	}

	patRepository := NewGormRepository(database)
	patController := NewHttpController(patRepository)

	patRouter := server.Group("/pats")

	patRouter.POST("/", patController.Create)
	patRouter.GET("/", patController.List)
	patRouter.DELETE("/:tokenId", patController.Delete)

	return server
}
